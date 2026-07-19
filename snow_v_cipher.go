package snowfive

import (
	"crypto/cipher"
	"errors"
	"runtime"
	"unsafe"
)

const (
	// KeySize is the SNOW-V and SNOW-Vi key size in bytes.
	KeySize = 32
	// IVSize is the SNOW-V and SNOW-Vi initialization-vector size in bytes.
	IVSize = 16
)

var (
	errWrongKeySize = errors.New("snowfive: wrong key size")
	errWrongIVSize  = errors.New("snowfive: wrong IV size")
)

// noCopy may be added to structs that must not be copied after first use.
// See https://golang.org/issues/8005#issuecomment-190753527.
type noCopy struct{}

// Lock and Unlock are no-ops used by go vet's copylocks analyzer.
func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}

type snowVState struct {
	lo [16]uint16 // a0..a7, then b0..b7
	hi [16]uint16 // a8..a15, then b8..b15
	r1 [4]uint32
	r2 [4]uint32
	r3 [4]uint32
}

type snowCipherState struct {
	state       snowVState
	blocks      uint64
	buf         [16]byte
	bufLen      uint8
	exhausted   bool
	initialized bool
}

// SnowVCipher is a SNOW-V stream cipher. A SnowVCipher must not be copied
// after first use, including by dereferencing it for formatting. Its methods
// are not safe for concurrent calls.
type SnowVCipher struct {
	noCopy noCopy
	snowCipherState
}

var _ cipher.Stream = (*SnowVCipher)(nil)

// NewSnowVCipher constructs a SNOW-V stream cipher from a 32-byte key and a
// 16-byte initialization vector. It reads but does not retain key or iv. The
// caller must ensure that iv is unique for key.
func NewSnowVCipher(key, iv []byte) (*SnowVCipher, error) {
	if len(key) != KeySize {
		return nil, errWrongKeySize
	}
	if len(iv) != IVSize {
		return nil, errWrongIVSize
	}
	return newSnowVCipher(new(SnowVCipher), key, iv), nil
}

//go:noinline
func newSnowVCipher(c *SnowVCipher, key, iv []byte) *SnowVCipher {
	initializeBackend(&c.state, key, iv)
	c.initialized = true
	return c
}

// Rekey initializes a zero-value cipher or replaces a live or destroyed
// cipher's state with a new key and IV. This supports a
// Destroy-Put/Get-Rekey sync.Pool lifecycle. Invalid key or IV lengths leave
// the existing state unchanged. The caller must ensure that iv is unique for
// key.
func (c *SnowVCipher) Rekey(key, iv []byte) error {
	if len(key) != KeySize {
		return errWrongKeySize
	}
	if len(iv) != IVSize {
		return errWrongIVSize
	}
	wipeSnowCipherState(&c.snowCipherState)
	initializeBackend(&c.state, key, iv)
	c.initialized = true
	runtime.KeepAlive(c)
	return nil
}

// XORKeyStream XORs src with the cipher stream and writes the result to dst.
// Dst may be longer than src, but otherwise must overlap src exactly or not at
// all. XORKeyStream panics before initialization and after Destroy until a
// successful Rekey.
func (c *SnowVCipher) XORKeyStream(dst, src []byte) {
	if !c.initialized {
		panic("snowfive: use of uninitialized SnowVCipher")
	}
	if len(src) == 0 {
		return
	}
	if len(dst) < len(src) {
		panic("snowfive: output smaller than input")
	}
	dst = dst[:len(src)]
	if inexactOverlap(dst, src) {
		panic("snowfive: invalid buffer overlap")
	}

	buffered := len(src)
	if buffered > int(c.bufLen) {
		buffered = int(c.bufLen)
	}
	remaining := len(src) - buffered
	newBlocks := uint64(remaining / 16)
	if remaining%16 != 0 {
		newBlocks++
	}

	prospectiveBlocks := c.blocks
	prospectiveExhausted := c.exhausted
	if newBlocks != 0 {
		if c.exhausted {
			panic("snowfive: keystream limit exceeded")
		}
		if c.blocks == 0 {
			prospectiveBlocks = newBlocks
		} else {
			available := -c.blocks
			if newBlocks > available {
				panic("snowfive: keystream limit exceeded")
			}
			if newBlocks == available {
				prospectiveBlocks = 0
				prospectiveExhausted = true
			} else {
				prospectiveBlocks += newBlocks
			}
		}
	}
	dstOffset := 0
	if buffered != 0 {
		bufOffset := 16 - int(c.bufLen)
		for i := 0; i < buffered; i++ {
			dst[i] = src[i] ^ c.buf[bufOffset+i]
		}
		c.bufLen -= uint8(buffered)
		dstOffset = buffered
	}

	fullLen := (remaining / 16) * 16
	if fullLen != 0 {
		xorBlocksBackend(&c.state, dst[dstOffset:dstOffset+fullLen], src[dstOffset:dstOffset+fullLen])
		dstOffset += fullLen
		remaining -= fullLen
	}
	if remaining != 0 {
		clear(c.buf[:])
		xorBlocksBackend(&c.state, c.buf[:], c.buf[:])
		for i := 0; i < remaining; i++ {
			dst[dstOffset+i] = src[dstOffset+i] ^ c.buf[i]
		}
		c.bufLen = uint8(16 - remaining)
	}

	c.blocks = prospectiveBlocks
	c.exhausted = prospectiveExhausted
}

func inexactOverlap(dst, src []byte) bool {
	dstp := uintptr(unsafe.Pointer(unsafe.SliceData(dst)))
	srcp := uintptr(unsafe.Pointer(unsafe.SliceData(src)))
	if dstp == srcp {
		return false
	}
	return dstp < srcp+uintptr(len(src)) && srcp < dstp+uintptr(len(dst))
}

// Destroy overwrites the cipher's live derived-key state and disables streaming
// until a successful Rekey. It is idempotent.
func (c *SnowVCipher) Destroy() {
	wipeSnowCipherState(&c.snowCipherState)
	runtime.KeepAlive(c)
}

//go:noinline
func wipeSnowCipherState(c *snowCipherState) {
	clear(c.state.lo[:])
	clear(c.state.hi[:])
	clear(c.state.r1[:])
	clear(c.state.r2[:])
	clear(c.state.r3[:])
	clear(c.buf[:])
	c.blocks = 0
	c.bufLen = 0
	c.exhausted = false
	c.initialized = false
}
