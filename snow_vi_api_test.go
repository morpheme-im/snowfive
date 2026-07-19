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

func requireSnowViPanic(t *testing.T, want string, operation func()) {
	t.Helper()
	defer func() {
		if got := recover(); got != want {
			t.Fatalf("panic = %v, want %q", got, want)
		}
	}()
	operation()
}

func TestSnowViNewCipherErrors(t *testing.T) {
	if cipher, err := NewSnowViCipher(make([]byte, KeySize-1), make([]byte, IVSize-1)); cipher != nil || err != errWrongKeySize || err.Error() != "snowfive: wrong key size" {
		t.Fatalf("wrong key result = (%v, %v)", cipher, err)
	}
	if cipher, err := NewSnowViCipher(make([]byte, KeySize), make([]byte, IVSize-1)); cipher != nil || err != errWrongIVSize || err.Error() != "snowfive: wrong IV size" {
		t.Fatalf("wrong IV result = (%v, %v)", cipher, err)
	}
}

func TestSnowViZeroValueRequiresRekey(t *testing.T) {
	var cipher SnowViCipher
	for _, test := range []struct {
		name string
		src  []byte
	}{
		{name: "empty"},
		{name: "non-empty", src: []byte{1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dst := []byte{0xa5}
			requireSnowViPanic(t, "snowfive: use of uninitialized SnowViCipher", func() {
				cipher.XORKeyStream(dst, test.src)
			})
			if dst[0] != 0xa5 {
				t.Fatalf("uninitialized call changed destination")
			}
		})
	}
}

func TestSnowViCipherFormattingRedactsState(t *testing.T) {
	cipher, err := NewSnowViCipher(make([]byte, KeySize), make([]byte, IVSize))
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

func TestSnowViStreamLengthsAndChunks(t *testing.T) {
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
			oneShot, err := NewSnowViCipher(key, iv)
			if err != nil {
				t.Fatal(err)
			}
			want := make([]byte, length)
			oneShot.XORKeyStream(want, src)
			if !bytes.Equal(src, plaintext[:length]) {
				t.Fatalf("source changed")
			}

			byteChunks, _ := NewSnowViCipher(key, iv)
			gotBytes := make([]byte, length)
			for i := range length {
				byteChunks.XORKeyStream(gotBytes[i:i+1], src[i:i+1])
			}
			if !bytes.Equal(gotBytes, want) {
				t.Fatalf("byte chunks differ")
			}

			irregular, _ := NewSnowViCipher(key, iv)
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

			inPlace, _ := NewSnowViCipher(key, iv)
			gotInPlace := append([]byte(nil), src...)
			inPlace.XORKeyStream(gotInPlace, gotInPlace)
			if !bytes.Equal(gotInPlace, want) {
				t.Fatalf("in-place output differs")
			}
		})
	}
}

func TestSnowViUnalignedSlices(t *testing.T) {
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
	unalignedKey := makeSnowViUnalignedSlice(t, KeySize, 11)
	unalignedIV := makeSnowViUnalignedSlice(t, IVSize, 13)
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

				reference, err := NewSnowViCipher(key, iv)
				if err != nil {
					t.Fatal(err)
				}
				want := make([]byte, length)
				reference.XORKeyStream(want, plaintext)

				src := makeSnowViUnalignedSlice(t, length, srcResidue)
				dst := makeSnowViUnalignedSlice(t, length, dstResidue)
				copy(src, plaintext)
				srcBefore := append([]byte(nil), src...)
				disjoint, err := NewSnowViCipher(unalignedKey, unalignedIV)
				if err != nil {
					t.Fatal(err)
				}
				disjoint.XORKeyStream(dst, src)
				if !bytes.Equal(dst, want) || !bytes.Equal(src, srcBefore) {
					t.Fatalf("unaligned disjoint output or source differs")
				}
				if snapshotSnowViCipher(disjoint) != snapshotSnowViCipher(reference) {
					t.Fatalf("unaligned disjoint final state differs")
				}

				inPlaceBuffer := makeSnowViUnalignedSlice(t, length, srcResidue)
				copy(inPlaceBuffer, plaintext)
				inPlace, _ := NewSnowViCipher(unalignedKey, unalignedIV)
				inPlace.XORKeyStream(inPlaceBuffer, inPlaceBuffer)
				if !bytes.Equal(inPlaceBuffer, want) {
					t.Fatalf("unaligned in-place output differs")
				}
				if snapshotSnowViCipher(inPlace) != snapshotSnowViCipher(reference) {
					t.Fatalf("unaligned in-place final state differs")
				}

				chunkedSrc := makeSnowViUnalignedSlice(t, length, srcResidue)
				chunkedDst := makeSnowViUnalignedSlice(t, length, dstResidue)
				copy(chunkedSrc, plaintext)
				chunked, _ := NewSnowViCipher(unalignedKey, unalignedIV)
				pattern := [...]int{1, 15, 16, 17, 31}
				for offset, chunk := 0, 0; offset < length; chunk++ {
					size := min(pattern[chunk%len(pattern)], length-offset)
					chunked.XORKeyStream(chunkedDst[offset:offset+size], chunkedSrc[offset:offset+size])
					offset += size
				}
				if !bytes.Equal(chunkedDst, want) {
					t.Fatalf("unaligned chunked output differs")
				}
				if !sameSnowViStreamPosition(chunked, reference) {
					t.Fatalf("unaligned chunked final state differs")
				}
			})
		}
	}
}

func makeSnowViUnalignedSlice(t *testing.T, length int, residue uintptr) []byte {
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

func sameSnowViStreamPosition(a, b *SnowViCipher) bool {
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

type snowViCipherSnapshot = snowCipherState

func snapshotSnowViCipher(cipher *SnowViCipher) snowViCipherSnapshot {
	return cipher.snowCipherState
}

func TestSnowViOverlapAndDestinationChecks(t *testing.T) {
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
			cipher, _ := NewSnowViCipher(key, iv)
			beforeCipher := snapshotSnowViCipher(cipher)
			buffer := make([]byte, 32)
			for i := range buffer {
				buffer[i] = byte(i)
			}
			beforeBuffer := append([]byte(nil), buffer...)
			requireSnowViPanic(t, "snowfive: invalid buffer overlap", func() {
				cipher.XORKeyStream(test.dst(buffer), test.src(buffer))
			})
			if snapshotSnowViCipher(cipher) != beforeCipher || !bytes.Equal(buffer, beforeBuffer) {
				t.Fatalf("rejected overlap mutated state or buffer")
			}
		})
	}

	cipher, _ := NewSnowViCipher(key, iv)
	beforeCipher := snapshotSnowViCipher(cipher)
	src := []byte{1, 2, 3, 4}
	dst := []byte{0xa5, 0xa5, 0xa5}
	beforeDst := append([]byte(nil), dst...)
	requireSnowViPanic(t, "snowfive: output smaller than input", func() {
		cipher.XORKeyStream(dst, src)
	})
	if snapshotSnowViCipher(cipher) != beforeCipher || !bytes.Equal(dst, beforeDst) {
		t.Fatalf("short destination mutated state or buffer")
	}

	adjacent, _ := NewSnowViCipher(key, iv)
	buffer := []byte{0, 0, 0, 0, 1, 2, 3, 4}
	adjacent.XORKeyStream(buffer[:8], buffer[4:8])
	if !bytes.Equal(buffer[4:8], []byte{1, 2, 3, 4}) {
		t.Fatalf("adjacent source changed")
	}
}

func TestSnowViDestroy(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, KeySize)
	iv := bytes.Repeat([]byte{0xa5}, IVSize)
	keyBefore := append([]byte(nil), key...)
	ivBefore := append([]byte(nil), iv...)
	cipher, err := NewSnowViCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	var oneByte [1]byte
	cipher.XORKeyStream(oneByte[:], oneByte[:])
	cipher.Destroy()
	if snapshotSnowViCipher(cipher) != (snowViCipherSnapshot{}) {
		t.Fatalf("destroy did not clear all sensitive fields: %+v", snapshotSnowViCipher(cipher))
	}
	cipher.Destroy()
	if snapshotSnowViCipher(cipher) != (snowViCipherSnapshot{}) {
		t.Fatalf("second destroy changed wiped state")
	}
	if !bytes.Equal(key, keyBefore) || !bytes.Equal(iv, ivBefore) {
		t.Fatalf("destroy changed caller key or IV")
	}

	emptyDst := []byte{0xa5}
	requireSnowViPanic(t, "snowfive: use of uninitialized SnowViCipher", func() {
		cipher.XORKeyStream(emptyDst, nil)
	})
	if emptyDst[0] != 0xa5 {
		t.Fatalf("post-destroy empty call changed destination")
	}
	nonemptyDst := []byte{0xa5}
	requireSnowViPanic(t, "snowfive: use of uninitialized SnowViCipher", func() {
		cipher.XORKeyStream(nonemptyDst, []byte{1})
	})
	if nonemptyDst[0] != 0xa5 {
		t.Fatalf("post-destroy call changed destination")
	}
}

func TestSnowViRekey(t *testing.T) {
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

	cipher, err := NewSnowViCipher(keyA[:], ivA[:])
	if err != nil {
		t.Fatal(err)
	}
	var prefix [23]byte
	cipher.XORKeyStream(prefix[:], prefix[:])

	beforeInvalid := snapshotSnowViCipher(cipher)
	if err := cipher.Rekey(keyB[:KeySize-1], ivB[:]); err != errWrongKeySize {
		t.Fatalf("short Rekey key error = %v", err)
	}
	if snapshotSnowViCipher(cipher) != beforeInvalid {
		t.Fatalf("short Rekey key mutated live state")
	}
	if err := cipher.Rekey(keyB[:], ivB[:IVSize-1]); err != errWrongIVSize {
		t.Fatalf("short Rekey IV error = %v", err)
	}
	if snapshotSnowViCipher(cipher) != beforeInvalid {
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
	assertSnowViRekeyMatchesFresh(t, cipher, keyB[:], ivB[:])
}

func TestSnowViRekeyAfterDestroyAndPool(t *testing.T) {
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

	cipher, err := NewSnowViCipher(keyA[:], ivA[:])
	if err != nil {
		t.Fatal(err)
	}
	var block [17]byte
	cipher.XORKeyStream(block[:], block[:])
	cipher.Destroy()
	wiped := snapshotSnowViCipher(cipher)
	if err := cipher.Rekey(keyB[:KeySize-1], ivB[:]); err != errWrongKeySize {
		t.Fatalf("destroyed Rekey error = %v", err)
	}
	if snapshotSnowViCipher(cipher) != wiped {
		t.Fatalf("invalid Rekey mutated destroyed state")
	}
	if err := cipher.Rekey(keyB[:], ivB[:]); err != nil {
		t.Fatal(err)
	}
	if !cipher.initialized {
		t.Fatalf("successful Rekey did not initialize cipher")
	}
	assertSnowViRekeyMatchesFresh(t, cipher, keyB[:], ivB[:])
	cipher.Destroy()

	var pool sync.Pool
	pool.New = func() any { return new(SnowViCipher) }
	pool.Put(cipher)
	pooled := pool.Get().(*SnowViCipher)
	if err := pooled.Rekey(keyA[:], ivA[:]); err != nil {
		t.Fatal(err)
	}
	if !pooled.initialized {
		t.Fatalf("successful pooled Rekey did not initialize cipher")
	}
	assertSnowViRekeyMatchesFresh(t, pooled, keyA[:], ivA[:])
	pooled.Destroy()
	pool.Put(pooled)
}

func assertSnowViRekeyMatchesFresh(t *testing.T, cipher *SnowViCipher, key, iv []byte) {
	t.Helper()
	fresh, err := NewSnowViCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if snapshotSnowViCipher(cipher) != snapshotSnowViCipher(fresh) {
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
	if snapshotSnowViCipher(cipher) != snapshotSnowViCipher(fresh) {
		t.Fatalf("Rekey final state differs from fresh cipher")
	}
}

func TestSnowViKeystreamLimit(t *testing.T) {
	key := make([]byte, KeySize)
	iv := make([]byte, IVSize)
	full, _ := NewSnowViCipher(key, iv)
	chunked, _ := NewSnowViCipher(key, iv)
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
	beforeCipher := snapshotSnowViCipher(chunked)
	beforeOutput := got
	requireSnowViPanic(t, "snowfive: keystream limit exceeded", func() {
		chunked.XORKeyStream(got[:1], got[:1])
	})
	if snapshotSnowViCipher(chunked) != beforeCipher || got != beforeOutput {
		t.Fatalf("terminal limit rejection mutated state or output")
	}

	rejected, _ := NewSnowViCipher(key, iv)
	rejected.blocks = math.MaxUint64
	var twoBlocks [32]byte
	beforeRejected := snapshotSnowViCipher(rejected)
	beforeTwoBlocks := twoBlocks
	requireSnowViPanic(t, "snowfive: keystream limit exceeded", func() {
		rejected.XORKeyStream(twoBlocks[:], twoBlocks[:])
	})
	if snapshotSnowViCipher(rejected) != beforeRejected || twoBlocks != beforeTwoBlocks {
		t.Fatalf("multi-block limit rejection mutated state or output")
	}
}

func TestSnowViZeroAllocations(t *testing.T) {
	var key [KeySize]byte
	var iv [IVSize]byte
	if allocations := testing.AllocsPerRun(1000, func() {
		cipher, err := NewSnowViCipher(key[:], iv[:])
		if err != nil {
			panic(err)
		}
		var block [16]byte
		cipher.XORKeyStream(block[:], block[:])
	}); allocations != 0 {
		t.Fatalf("local constructor and stream allocations = %v, want 0", allocations)
	}

	stream, _ := NewSnowViCipher(key[:], iv[:])
	var src, dst [16]byte
	if allocations := testing.AllocsPerRun(1000, func() {
		stream.XORKeyStream(dst[:], src[:])
	}); allocations != 0 {
		t.Fatalf("XORKeyStream allocations = %v, want 0", allocations)
	}

	var generic snowVState
	initializeViGeneric(&generic, key[:], iv[:])
	if allocations := testing.AllocsPerRun(1000, func() {
		xorBlocksViGeneric(&generic, dst[:], src[:])
	}); allocations != 0 {
		t.Fatalf("generic block allocations = %v, want 0", allocations)
	}

	var backend snowVState
	if allocations := testing.AllocsPerRun(1000, func() {
		initializeViBackend(&backend, key[:], iv[:])
	}); allocations != 0 {
		t.Fatalf("backend initialization allocations = %v, want 0", allocations)
	}
	if allocations := testing.AllocsPerRun(1000, func() {
		xorBlocksViBackend(&backend, dst[:], src[:])
	}); allocations != 0 {
		t.Fatalf("backend block allocations = %v, want 0", allocations)
	}

	toDestroy, _ := NewSnowViCipher(key[:], iv[:])
	if allocations := testing.AllocsPerRun(1000, func() {
		toDestroy.Destroy()
	}); allocations != 0 {
		t.Fatalf("Destroy allocations = %v, want 0", allocations)
	}
}

func TestSnowViCallerBuffersAndDestinationSuffix(t *testing.T) {
	key := make([]byte, KeySize)
	iv := make([]byte, IVSize)
	for i := range key {
		key[i] = byte(i*7 + 1)
	}
	for i := range iv {
		iv[i] = byte(i*11 + 3)
	}
	keyBefore := append([]byte(nil), key...)
	ivBefore := append([]byte(nil), iv...)
	src := make([]byte, 255)
	for i := range src {
		src[i] = byte(i*13 + 5)
	}
	srcBefore := append([]byte(nil), src...)
	dst := bytes.Repeat([]byte{0xa5}, len(src)+17)
	cipher, err := NewSnowViCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	cipher.XORKeyStream(dst, src)
	if !bytes.Equal(key, keyBefore) || !bytes.Equal(iv, ivBefore) {
		t.Fatal("constructor or stream changed caller key or IV")
	}
	if !bytes.Equal(src, srcBefore) {
		t.Fatal("stream changed disjoint source")
	}
	if !bytes.Equal(dst[len(src):], bytes.Repeat([]byte{0xa5}, 17)) {
		t.Fatal("stream changed destination suffix")
	}
}

func TestSnowViAllAlignmentsAndCanaries(t *testing.T) {
	key := make([]byte, KeySize)
	iv := make([]byte, IVSize)
	plaintext := make([]byte, 255)
	for i := range key {
		key[i] = byte(i*17 + 1)
	}
	for i := range iv {
		iv[i] = byte(i*19 + 3)
	}
	for i := range plaintext {
		plaintext[i] = byte(i*23 + 7)
	}
	reference, _ := NewSnowViCipher(key, iv)
	want := make([]byte, len(plaintext))
	reference.XORKeyStream(want, plaintext)

	for residue := uintptr(1); residue < 16; residue++ {
		t.Run(strconv.FormatUint(uint64(residue), 10), func(t *testing.T) {
			unalignedKey, keyBacking, keyStart := makeGuardedSnowViSlice(t, KeySize, residue)
			unalignedIV, ivBacking, ivStart := makeGuardedSnowViSlice(t, IVSize, residue%15+1)
			copy(unalignedKey, key)
			copy(unalignedIV, iv)
			src, srcBacking, srcStart := makeGuardedSnowViSlice(t, len(plaintext), residue)
			dst, dstBacking, dstStart := makeGuardedSnowViSlice(t, len(plaintext), 16-residue)
			copy(src, plaintext)
			srcBefore := append([]byte(nil), src...)
			cipher, _ := NewSnowViCipher(unalignedKey, unalignedIV)
			cipher.XORKeyStream(dst, src)
			if !bytes.Equal(dst, want) || !bytes.Equal(src, srcBefore) {
				t.Fatal("unaligned disjoint stream differs")
			}
			assertSnowViCanaries(t, srcBacking, srcStart, len(src))
			assertSnowViCanaries(t, dstBacking, dstStart, len(dst))

			inPlace, backing, start := makeGuardedSnowViSlice(t, len(plaintext), residue)
			copy(inPlace, plaintext)
			cipher, _ = NewSnowViCipher(unalignedKey, unalignedIV)
			cipher.XORKeyStream(inPlace, inPlace)
			if !bytes.Equal(inPlace, want) {
				t.Fatal("unaligned in-place stream differs")
			}
			assertSnowViCanaries(t, backing, start, len(inPlace))
			assertSnowViCanaries(t, keyBacking, keyStart, len(unalignedKey))
			assertSnowViCanaries(t, ivBacking, ivStart, len(unalignedIV))
			if !bytes.Equal(unalignedKey, key) || !bytes.Equal(unalignedIV, iv) {
				t.Fatal("unaligned constructor changed key or IV")
			}
		})
	}
}

func makeGuardedSnowViSlice(t *testing.T, length int, residue uintptr) ([]byte, []byte, int) {
	t.Helper()
	backing := bytes.Repeat([]byte{0xa5}, length+32)
	base := uintptr(unsafe.Pointer(unsafe.SliceData(backing)))
	start := int((residue + 16 - base%16) % 16)
	result := backing[start : start+length]
	if got := uintptr(unsafe.Pointer(unsafe.SliceData(result))) % 16; got != residue {
		t.Fatalf("slice address modulo 16 = %d, want %d", got, residue)
	}
	return result, backing, start
}

func assertSnowViCanaries(t *testing.T, backing []byte, start, length int) {
	t.Helper()
	for index, value := range backing[:start] {
		if value != 0xa5 {
			t.Fatalf("prefix canary %d changed", index)
		}
	}
	for index, value := range backing[start+length:] {
		if value != 0xa5 {
			t.Fatalf("suffix canary %d changed", index)
		}
	}
}

func TestSnowViZeroValueRekey(t *testing.T) {
	var key [KeySize]byte
	var iv [IVSize]byte
	for i := range key {
		key[i] = byte(i*29 + 1)
	}
	for i := range iv {
		iv[i] = byte(i*31 + 5)
	}
	var cipher SnowViCipher
	if err := cipher.Rekey(key[:], iv[:]); err != nil {
		t.Fatal(err)
	}
	assertSnowViRekeyMatchesFresh(t, &cipher, key[:], iv[:])
}
