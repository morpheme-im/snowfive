package snowfive

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"unsafe"
)

func requirePanic(t *testing.T, want string, operation func()) {
	t.Helper()
	defer func() {
		if got := recover(); got != want {
			t.Fatalf("panic = %v, want %q", got, want)
		}
	}()
	operation()
}

func TestSnowVNewSnowVCipherErrors(t *testing.T) {
	if cipher, err := NewSnowVCipher(make([]byte, KeySize-1), make([]byte, IVSize-1)); cipher != nil || err != errWrongKeySize || err.Error() != "snowfive: wrong key size" {
		t.Fatalf("wrong key result = (%v, %v)", cipher, err)
	}
	if cipher, err := NewSnowVCipher(make([]byte, KeySize), make([]byte, IVSize-1)); cipher != nil || err != errWrongIVSize || err.Error() != "snowfive: wrong IV size" {
		t.Fatalf("wrong IV result = (%v, %v)", cipher, err)
	}
}

func TestSnowVZeroValueRequiresRekey(t *testing.T) {
	var cipher SnowVCipher
	for _, test := range []struct {
		name string
		src  []byte
	}{
		{name: "empty"},
		{name: "non-empty", src: []byte{1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dst := []byte{0xa5}
			requirePanic(t, "snowfive: use of uninitialized SnowVCipher", func() {
				cipher.XORKeyStream(dst, test.src)
			})
			if dst[0] != 0xa5 {
				t.Fatalf("uninitialized call changed destination")
			}
		})
	}
}

func TestSnowVCipherFormattingRedactsState(t *testing.T) {
	cipher, err := NewSnowVCipher(make([]byte, KeySize), make([]byte, IVSize))
	if err != nil {
		t.Fatal(err)
	}
	values := []any{
		cipher,
		reflect.ValueOf(cipher).Elem().Interface(),
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			if got := fmt.Sprintf(format, value); got != redactedCipherState {
				t.Fatalf("format %q = %q, want %q", format, got, redactedCipherState)
			}
		}
	}
}

func TestSnowVStreamLengthsAndChunks(t *testing.T) {
	lengths := []int{0, 1, 15, 16, 17, 31, 32, 63, 64, 255, 1024}
	key := make([]byte, KeySize)
	iv := make([]byte, IVSize)
	plaintext := make([]byte, 1024)
	for i := range plaintext {
		plaintext[i] = byte(i*29 + 7)
	}
	for _, length := range lengths {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			src := append([]byte(nil), plaintext[:length]...)
			oneShot, err := NewSnowVCipher(key, iv)
			if err != nil {
				t.Fatal(err)
			}
			want := make([]byte, length)
			oneShot.XORKeyStream(want, src)
			if !bytes.Equal(src, plaintext[:length]) {
				t.Fatalf("source changed")
			}

			byteChunks, _ := NewSnowVCipher(key, iv)
			gotBytes := make([]byte, length)
			for i := range length {
				byteChunks.XORKeyStream(gotBytes[i:i+1], src[i:i+1])
			}
			if !bytes.Equal(gotBytes, want) {
				t.Fatalf("byte chunks differ")
			}

			irregular, _ := NewSnowVCipher(key, iv)
			gotIrregular := make([]byte, length)
			pattern := [...]int{17, 1, 31, 2, 64, 3, 15}
			for offset, chunk := 0, 0; offset < length; chunk++ {
				size := pattern[chunk%len(pattern)]
				if size > length-offset {
					size = length - offset
				}
				irregular.XORKeyStream(gotIrregular[offset:offset+size], src[offset:offset+size])
				offset += size
			}
			if !bytes.Equal(gotIrregular, want) {
				t.Fatalf("irregular chunks differ")
			}

			inPlace, _ := NewSnowVCipher(key, iv)
			gotInPlace := append([]byte(nil), src...)
			inPlace.XORKeyStream(gotInPlace, gotInPlace)
			if !bytes.Equal(gotInPlace, want) {
				t.Fatalf("in-place output differs")
			}
		})
	}
}

func TestSnowVUnalignedSlices(t *testing.T) {
	lengths := [...]int{1, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 255, 256, 1024}
	residues := [...]uintptr{1, 3, 7, 15}

	key := make([]byte, KeySize)
	iv := make([]byte, IVSize)
	for i := range key {
		key[i] = byte(i*13 + 5)
	}
	for i := range iv {
		iv[i] = byte(i*17 + 9)
	}
	unalignedKey := makeUnalignedSlice(t, KeySize, 11)
	unalignedIV := makeUnalignedSlice(t, IVSize, 13)
	copy(unalignedKey, key)
	copy(unalignedIV, iv)

	for _, length := range lengths {
		for index, srcResidue := range residues {
			dstResidue := residues[(index+1)%len(residues)]
			name := strconv.Itoa(length) + "/src-" + strconv.FormatUint(uint64(srcResidue), 10) + "/dst-" + strconv.FormatUint(uint64(dstResidue), 10)
			t.Run(name, func(t *testing.T) {
				plaintext := make([]byte, length)
				for i := range plaintext {
					plaintext[i] = byte(i*29 + 7)
				}

				reference, err := NewSnowVCipher(key, iv)
				if err != nil {
					t.Fatal(err)
				}
				want := make([]byte, length)
				reference.XORKeyStream(want, plaintext)

				src := makeUnalignedSlice(t, length, srcResidue)
				dst := makeUnalignedSlice(t, length, dstResidue)
				copy(src, plaintext)
				srcBefore := append([]byte(nil), src...)
				disjoint, err := NewSnowVCipher(unalignedKey, unalignedIV)
				if err != nil {
					t.Fatal(err)
				}
				disjoint.XORKeyStream(dst, src)
				if !bytes.Equal(dst, want) || !bytes.Equal(src, srcBefore) {
					t.Fatalf("unaligned disjoint output or source differs")
				}
				if snapshotCipher(disjoint) != snapshotCipher(reference) {
					t.Fatalf("unaligned disjoint final state differs")
				}

				inPlaceBuffer := makeUnalignedSlice(t, length, srcResidue)
				copy(inPlaceBuffer, plaintext)
				inPlace, _ := NewSnowVCipher(unalignedKey, unalignedIV)
				inPlace.XORKeyStream(inPlaceBuffer, inPlaceBuffer)
				if !bytes.Equal(inPlaceBuffer, want) {
					t.Fatalf("unaligned in-place output differs")
				}
				if snapshotCipher(inPlace) != snapshotCipher(reference) {
					t.Fatalf("unaligned in-place final state differs")
				}

				chunkedSrc := makeUnalignedSlice(t, length, srcResidue)
				chunkedDst := makeUnalignedSlice(t, length, dstResidue)
				copy(chunkedSrc, plaintext)
				chunked, _ := NewSnowVCipher(unalignedKey, unalignedIV)
				pattern := [...]int{1, 15, 16, 17, 31}
				for offset, chunk := 0, 0; offset < length; chunk++ {
					size := min(pattern[chunk%len(pattern)], length-offset)
					chunked.XORKeyStream(chunkedDst[offset:offset+size], chunkedSrc[offset:offset+size])
					offset += size
				}
				if !bytes.Equal(chunkedDst, want) {
					t.Fatalf("unaligned chunked output differs")
				}
				if !sameStreamPosition(chunked, reference) {
					t.Fatalf("unaligned chunked final state differs")
				}
			})
		}
	}
}

func makeUnalignedSlice(t *testing.T, length int, residue uintptr) []byte {
	t.Helper()
	backing := make([]byte, length+16)
	base := uintptr(unsafe.Pointer(unsafe.SliceData(backing)))
	offset := int((residue + 16 - base%16) % 16)
	slice := backing[offset : offset+length]
	if got := uintptr(unsafe.Pointer(unsafe.SliceData(slice))) % 16; got != residue {
		t.Fatalf("slice address modulo 16 = %d, want %d", got, residue)
	}
	return slice
}

func sameStreamPosition(a, b *SnowVCipher) bool {
	if a.state != b.state ||
		a.blocks != b.blocks ||
		a.bufLen != b.bufLen ||
		a.exhausted != b.exhausted ||
		a.initialized != b.initialized {
		return false
	}
	if a.bufLen == 0 {
		return true
	}
	offset := len(a.buf) - int(a.bufLen)
	return bytes.Equal(a.buf[offset:], b.buf[offset:])
}

type cipherSnapshot struct {
	state       snowVState
	blocks      uint64
	buf         [16]byte
	bufLen      uint8
	exhausted   bool
	initialized bool
}

func snapshotCipher(cipher *SnowVCipher) cipherSnapshot {
	return cipherSnapshot{
		state:       cipher.state,
		blocks:      cipher.blocks,
		buf:         cipher.buf,
		bufLen:      cipher.bufLen,
		exhausted:   cipher.exhausted,
		initialized: cipher.initialized,
	}
}

func TestSnowVOverlapAndDestinationChecks(t *testing.T) {
	key := make([]byte, KeySize)
	iv := make([]byte, IVSize)
	for _, test := range []struct {
		name string
		dst  func([]byte) []byte
		src  func([]byte) []byte
	}{
		{"dst-after-src", func(buffer []byte) []byte { return buffer[1:17] }, func(buffer []byte) []byte { return buffer[:16] }},
		{"dst-before-src", func(buffer []byte) []byte { return buffer[:16] }, func(buffer []byte) []byte { return buffer[1:17] }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cipher, _ := NewSnowVCipher(key, iv)
			beforeCipher := snapshotCipher(cipher)
			buffer := make([]byte, 32)
			for i := range buffer {
				buffer[i] = byte(i)
			}
			beforeBuffer := append([]byte(nil), buffer...)
			requirePanic(t, "snowfive: invalid buffer overlap", func() {
				cipher.XORKeyStream(test.dst(buffer), test.src(buffer))
			})
			if snapshotCipher(cipher) != beforeCipher || !bytes.Equal(buffer, beforeBuffer) {
				t.Fatalf("rejected overlap mutated state or buffer")
			}
		})
	}

	cipher, _ := NewSnowVCipher(key, iv)
	beforeCipher := snapshotCipher(cipher)
	src := []byte{1, 2, 3, 4}
	dst := []byte{0xa5, 0xa5, 0xa5}
	beforeDst := append([]byte(nil), dst...)
	requirePanic(t, "snowfive: output smaller than input", func() {
		cipher.XORKeyStream(dst, src)
	})
	if snapshotCipher(cipher) != beforeCipher || !bytes.Equal(dst, beforeDst) {
		t.Fatalf("short destination mutated state or buffer")
	}

	adjacent, _ := NewSnowVCipher(key, iv)
	buffer := []byte{0, 0, 0, 0, 1, 2, 3, 4}
	adjacent.XORKeyStream(buffer[:8], buffer[4:8])
	if !bytes.Equal(buffer[4:8], []byte{1, 2, 3, 4}) {
		t.Fatalf("adjacent source changed")
	}
}

func TestSnowVDestroy(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, KeySize)
	iv := bytes.Repeat([]byte{0xa5}, IVSize)
	keyBefore := append([]byte(nil), key...)
	ivBefore := append([]byte(nil), iv...)
	cipher, err := NewSnowVCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	var oneByte [1]byte
	cipher.XORKeyStream(oneByte[:], oneByte[:])
	cipher.Destroy()
	if snapshotCipher(cipher) != (cipherSnapshot{}) {
		t.Fatalf("destroy did not clear all sensitive fields: %+v", snapshotCipher(cipher))
	}
	cipher.Destroy()
	if snapshotCipher(cipher) != (cipherSnapshot{}) {
		t.Fatalf("second destroy changed wiped state")
	}
	if !bytes.Equal(key, keyBefore) || !bytes.Equal(iv, ivBefore) {
		t.Fatalf("destroy changed caller key or IV")
	}

	emptyDst := []byte{0xa5}
	requirePanic(t, "snowfive: use of uninitialized SnowVCipher", func() {
		cipher.XORKeyStream(emptyDst, nil)
	})
	if emptyDst[0] != 0xa5 {
		t.Fatalf("post-destroy empty call changed destination")
	}
	nonemptyDst := []byte{0xa5}
	requirePanic(t, "snowfive: use of uninitialized SnowVCipher", func() {
		cipher.XORKeyStream(nonemptyDst, []byte{1})
	})
	if nonemptyDst[0] != 0xa5 {
		t.Fatalf("post-destroy call changed destination")
	}
}

func TestSnowVRekey(t *testing.T) {
	var keyA, keyB [KeySize]byte
	var ivA, ivB [IVSize]byte
	for i := range keyA {
		keyA[i] = byte(i*11 + 1)
		keyB[i] = byte(i*13 + 7)
	}
	for i := range ivA {
		ivA[i] = byte(i*17 + 3)
		ivB[i] = byte(i*19 + 9)
	}

	cipher, err := NewSnowVCipher(keyA[:], ivA[:])
	if err != nil {
		t.Fatal(err)
	}
	var prefix [23]byte
	cipher.XORKeyStream(prefix[:], prefix[:])

	beforeInvalid := snapshotCipher(cipher)
	if err := cipher.Rekey(keyB[:KeySize-1], ivB[:]); err != errWrongKeySize {
		t.Fatalf("short Rekey key error = %v", err)
	}
	if snapshotCipher(cipher) != beforeInvalid {
		t.Fatalf("short Rekey key mutated live state")
	}
	if err := cipher.Rekey(keyB[:], ivB[:IVSize-1]); err != errWrongIVSize {
		t.Fatalf("short Rekey IV error = %v", err)
	}
	if snapshotCipher(cipher) != beforeInvalid {
		t.Fatalf("short Rekey IV mutated live state")
	}

	keyBefore := keyB
	ivBefore := ivB
	if err := cipher.Rekey(keyB[:], ivB[:]); err != nil {
		t.Fatal(err)
	}
	if keyB != keyBefore || ivB != ivBefore {
		t.Fatalf("Rekey mutated caller key or IV")
	}
	assertRekeyMatchesFresh(t, cipher, keyB[:], ivB[:])
}

func TestSnowVRekeyAfterDestroyAndPool(t *testing.T) {
	var keyA, keyB [KeySize]byte
	var ivA, ivB [IVSize]byte
	for i := range keyA {
		keyA[i] = byte(i*23 + 1)
		keyB[i] = byte(i*29 + 5)
	}
	for i := range ivA {
		ivA[i] = byte(i*31 + 7)
		ivB[i] = byte(i*37 + 11)
	}

	cipher, err := NewSnowVCipher(keyA[:], ivA[:])
	if err != nil {
		t.Fatal(err)
	}
	var block [17]byte
	cipher.XORKeyStream(block[:], block[:])
	cipher.Destroy()
	wiped := snapshotCipher(cipher)
	if err := cipher.Rekey(keyB[:KeySize-1], ivB[:]); err != errWrongKeySize {
		t.Fatalf("destroyed Rekey error = %v", err)
	}
	if snapshotCipher(cipher) != wiped {
		t.Fatalf("invalid Rekey mutated destroyed state")
	}
	if err := cipher.Rekey(keyB[:], ivB[:]); err != nil {
		t.Fatal(err)
	}
	if !cipher.initialized {
		t.Fatalf("successful Rekey did not initialize cipher")
	}
	assertRekeyMatchesFresh(t, cipher, keyB[:], ivB[:])
	cipher.Destroy()

	var pool sync.Pool
	pool.New = func() any { return new(SnowVCipher) }
	pool.Put(cipher)
	pooled := pool.Get().(*SnowVCipher)
	if err := pooled.Rekey(keyA[:], ivA[:]); err != nil {
		t.Fatal(err)
	}
	if !pooled.initialized {
		t.Fatalf("successful pooled Rekey did not initialize cipher")
	}
	assertRekeyMatchesFresh(t, pooled, keyA[:], ivA[:])
	pooled.Destroy()
	pool.Put(pooled)
}

func assertRekeyMatchesFresh(t *testing.T, cipher *SnowVCipher, key, iv []byte) {
	t.Helper()
	fresh, err := NewSnowVCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if snapshotCipher(cipher) != snapshotCipher(fresh) {
		t.Fatalf("Rekey state differs from fresh cipher")
	}
	src := make([]byte, 257)
	for i := range src {
		src[i] = byte(i*41 + 13)
	}
	got := make([]byte, len(src))
	want := make([]byte, len(src))
	cipher.XORKeyStream(got, src)
	fresh.XORKeyStream(want, src)
	if !bytes.Equal(got, want) {
		t.Fatalf("Rekey stream differs from fresh cipher")
	}
	if snapshotCipher(cipher) != snapshotCipher(fresh) {
		t.Fatalf("Rekey final state differs from fresh cipher")
	}
}

func TestSnowVKeystreamLimit(t *testing.T) {
	key := make([]byte, KeySize)
	iv := make([]byte, IVSize)
	full, _ := NewSnowVCipher(key, iv)
	chunked, _ := NewSnowVCipher(key, iv)
	full.blocks = math.MaxUint64
	chunked.blocks = math.MaxUint64
	var want, got [16]byte
	full.XORKeyStream(want[:], want[:])
	chunked.XORKeyStream(got[:1], got[:1])
	if chunked.blocks != 0 || !chunked.exhausted || chunked.bufLen != 15 {
		t.Fatalf("terminal partial block accounting is wrong")
	}
	chunked.XORKeyStream(got[1:], got[1:])
	if got != want || chunked.bufLen != 0 || chunked.blocks != 0 || !chunked.exhausted {
		t.Fatalf("buffered terminal block was not consumable")
	}
	beforeCipher := snapshotCipher(chunked)
	beforeOutput := got
	requirePanic(t, "snowfive: keystream limit exceeded", func() {
		chunked.XORKeyStream(got[:1], got[:1])
	})
	if snapshotCipher(chunked) != beforeCipher || got != beforeOutput {
		t.Fatalf("terminal limit rejection mutated state or output")
	}

	rejected, _ := NewSnowVCipher(key, iv)
	rejected.blocks = math.MaxUint64
	var twoBlocks [32]byte
	beforeRejected := snapshotCipher(rejected)
	beforeTwoBlocks := twoBlocks
	requirePanic(t, "snowfive: keystream limit exceeded", func() {
		rejected.XORKeyStream(twoBlocks[:], twoBlocks[:])
	})
	if snapshotCipher(rejected) != beforeRejected || twoBlocks != beforeTwoBlocks {
		t.Fatalf("multi-block limit rejection mutated state or output")
	}
}

func TestSnowVZeroAllocations(t *testing.T) {
	var key [KeySize]byte
	var iv [IVSize]byte
	if allocations := testing.AllocsPerRun(1000, func() {
		cipher, err := NewSnowVCipher(key[:], iv[:])
		if err != nil {
			panic(err)
		}
		var block [16]byte
		cipher.XORKeyStream(block[:], block[:])
	}); allocations != 0 {
		t.Fatalf("local constructor and stream allocations = %v, want 0", allocations)
	}

	stream, _ := NewSnowVCipher(key[:], iv[:])
	var src, dst [16]byte
	if allocations := testing.AllocsPerRun(1000, func() {
		stream.XORKeyStream(dst[:], src[:])
	}); allocations != 0 {
		t.Fatalf("XORKeyStream allocations = %v, want 0", allocations)
	}

	var generic snowVState
	initializeGeneric(&generic, key[:], iv[:])
	if allocations := testing.AllocsPerRun(1000, func() {
		xorBlocksGeneric(&generic, dst[:], src[:])
	}); allocations != 0 {
		t.Fatalf("generic block allocations = %v, want 0", allocations)
	}

	var backend snowVState
	if allocations := testing.AllocsPerRun(1000, func() {
		initializeBackend(&backend, key[:], iv[:])
	}); allocations != 0 {
		t.Fatalf("backend initialization allocations = %v, want 0", allocations)
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		xorBlocksBackend(&backend, dst[:], src[:])
	}); allocations != 0 {
		t.Fatalf("backend block allocations = %v, want 0", allocations)
	}

	toDestroy, _ := NewSnowVCipher(key[:], iv[:])
	if allocations := testing.AllocsPerRun(1000, func() {
		toDestroy.Destroy()
	}); allocations != 0 {
		t.Fatalf("Destroy allocations = %v, want 0", allocations)
	}
}
