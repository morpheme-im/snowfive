package snowfive

import (
	"crypto/cipher"
	"runtime"
)

// SnowViCipher is a SNOW-Vi stream cipher. A SnowViCipher must not be copied
// after first use, including by dereferencing it for formatting. Its methods
// are not safe for concurrent calls.
type SnowViCipher struct {
	noCopy noCopy
	snowCipherState
}

var _ cipher.Stream = (*SnowViCipher)(nil)

// NewSnowViCipher constructs a SNOW-Vi stream cipher from a 32-byte key and a
// 16-byte initialization vector. It reads but does not retain key or iv. The
// caller must ensure that iv is unique for key.
func NewSnowViCipher(key, iv []byte) (*SnowViCipher, error) {
	if len(key) != KeySize {
		return nil, errWrongKeySize
	}
	if len(iv) != IVSize {
		return nil, errWrongIVSize
	}
	return newSnowViCipher(new(SnowViCipher), key, iv), nil
}

//go:noinline
func newSnowViCipher(c *SnowViCipher, key, iv []byte) *SnowViCipher {
	initializeViBackend(&c.state, key, iv)
	c.initialized = true
	return c
}

// Rekey initializes a zero-value cipher or replaces a live or destroyed
// cipher's state with a new key and IV. This supports a
// Destroy-Put/Get-Rekey sync.Pool lifecycle. Invalid key or IV lengths leave
// the existing state unchanged. The caller must ensure that iv is unique for
// key.
func (c *SnowViCipher) Rekey(key, iv []byte) error {
	if len(key) != KeySize {
		return errWrongKeySize
	}
	if len(iv) != IVSize {
		return errWrongIVSize
	}
	wipeSnowCipherState(&c.snowCipherState)
	initializeViBackend(&c.state, key, iv)
	c.initialized = true
	runtime.KeepAlive(c)
	return nil
}

// XORKeyStream XORs src with the cipher stream and writes the result to dst.
// Dst may be longer than src, but otherwise must overlap src exactly or not at
// all. XORKeyStream panics before initialization and after Destroy until a
// successful Rekey.
func (c *SnowViCipher) XORKeyStream(dst, src []byte) {
	if !c.initialized {
		panic("snowfive: use of uninitialized SnowViCipher")
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
		xorBlocksViBackend(&c.state, dst[dstOffset:dstOffset+fullLen], src[dstOffset:dstOffset+fullLen])
		dstOffset += fullLen
		remaining -= fullLen
	}
	if remaining != 0 {
		clear(c.buf[:])
		xorBlocksViBackend(&c.state, c.buf[:], c.buf[:])
		for i := 0; i < remaining; i++ {
			dst[dstOffset+i] = src[dstOffset+i] ^ c.buf[i]
		}
		c.bufLen = uint8(16 - remaining)
	}

	c.blocks = prospectiveBlocks
	c.exhausted = prospectiveExhausted
}

// Destroy overwrites the cipher's live derived-key state and disables streaming
// until a successful Rekey. It is idempotent.
func (c *SnowViCipher) Destroy() {
	wipeSnowCipherState(&c.snowCipherState)
	runtime.KeepAlive(c)
}
