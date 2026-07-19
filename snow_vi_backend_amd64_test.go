//go:build amd64 && !purego && !noasm

package snowfive

import (
	"bytes"
	"math/rand/v2"
	"testing"
	"unsafe"
)

func TestSnowViAESRoundPairAES(t *testing.T) {
	if !hasAESAMD64 {
		t.Skip("AES-NI unavailable")
	}
	random := rand.New(rand.NewPCG(0x4145534e49, 0x20181143))
	for testCase := range 1000 {
		var srcR1, srcR2 [4]uint32
		for i := range 4 {
			srcR1[i] = random.Uint32()
			srcR2[i] = random.Uint32()
		}
		wantR2 := aesRoundReference(srcR1)
		wantR3 := aesRoundReference(srcR2)
		aliasR2 := srcR2
		var gotR3 [4]uint32
		aesRoundPairAES(&aliasR2, &gotR3, &srcR1, &aliasR2)
		if aliasR2 != wantR2 || gotR3 != wantR3 {
			t.Fatalf("case %d: aliased AES pair differs", testCase)
		}
	}
}

func TestSnowViDirectBackendDifferentialAMD64(t *testing.T) {
	if !hasAESAMD64 {
		t.Skip("AES-NI unavailable")
	}
	random := rand.New(rand.NewPCG(0x414d443634, 0x20181143))
	for testCase := range 100 {
		key := make([]byte, KeySize)
		iv := make([]byte, IVSize)
		fillDeterministic(random, key)
		fillDeterministic(random, iv)
		var generic, aesOnly snowVState
		initializeViGeneric(&generic, key, iv)
		initializeViAESAMD64(&aesOnly, key, iv)
		if aesOnly != generic {
			t.Fatalf("case %d: AES-only initialization differs", testCase)
		}
		for block := range 64 {
			var src, want, got [16]byte
			fillDeterministic(random, src[:])
			xorBlocksViGeneric(&generic, want[:], src[:])
			xorBlocksViAESAMD64(&aesOnly, got[:], src[:])
			if got != want || aesOnly != generic {
				t.Fatalf("case %d block %d: AES-only backend differs", testCase, block)
			}
		}
	}

	if hasSSSE3AMD64 {
		testSnowViBackendDifferentialTierAMD64(t, "XMM", 0x584d4d32, initStateViXMM, xorBlocksViXMM)
	}
	if hasVAESAMD64 {
		testSnowViBackendDifferentialTierAMD64(t, "VAES", 0x56414553, initStateViAVX2, xorBlocksViAVX2)
	}
}

type snowViAMD64StateInitializer func(*snowVState, *byte, *byte)

type snowViAMD64BlockXOR func(*snowVState, *byte, *byte, uintptr)

func testSnowViBackendDifferentialTierAMD64(t *testing.T, name string, seed uint64, initialize snowViAMD64StateInitializer, xor snowViAMD64BlockXOR) {
	t.Helper()
	random := rand.New(rand.NewPCG(seed, 0x20181143))
	for testCase := range 100 {
		key := make([]byte, KeySize)
		iv := make([]byte, IVSize)
		fillDeterministic(random, key)
		fillDeterministic(random, iv)
		var generic, assembly snowVState
		initializeViGeneric(&generic, key, iv)
		initialize(&assembly, unsafe.SliceData(key), unsafe.SliceData(iv))
		if assembly != generic {
			t.Fatalf("%s case %d: initialization differs", name, testCase)
		}
		for block := range 64 {
			var src, want, got [16]byte
			fillDeterministic(random, src[:])
			xorBlocksViGeneric(&generic, want[:], src[:])
			xor(&assembly, unsafe.SliceData(got[:]), unsafe.SliceData(src[:]), 1)
			if got != want || assembly != generic {
				t.Fatalf("%s case %d block %d: backend differs", name, testCase, block)
			}
		}
	}
}

func TestSnowViDirectBackendBatchesAMD64(t *testing.T) {
	ran := false
	if hasAESAMD64 && hasSSSE3AMD64 {
		ran = true
		t.Run("XMM", func(t *testing.T) {
			testSnowViBackendBatchesTierAMD64(t, "XMM", initStateViXMM, xorBlocksViXMM)
		})
	}
	if hasVAESAMD64 {
		ran = true
		t.Run("VAES", func(t *testing.T) {
			testSnowViBackendBatchesTierAMD64(t, "VAES", initStateViAVX2, xorBlocksViAVX2)
		})
	}
	if !ran {
		t.Skip("AES-NI/SSSE3 unavailable")
	}
}

func testSnowViBackendBatchesTierAMD64(t *testing.T, name string, initialize snowViAMD64StateInitializer, xor snowViAMD64BlockXOR) {
	t.Helper()
	random := rand.New(rand.NewPCG(0x4241544348, 0x414d4436))
	key := makeUnalignedSlice(t, KeySize, 1)
	iv := makeUnalignedSlice(t, IVSize, 3)
	fillDeterministic(random, key)
	fillDeterministic(random, iv)
	for blocks := 1; blocks <= 33; blocks++ {
		src := make([]byte, 16*blocks)
		fillDeterministic(random, src)
		var generic, assembly snowVState
		initializeViGeneric(&generic, key, iv)
		initialize(&assembly, unsafe.SliceData(key), unsafe.SliceData(iv))
		want := make([]byte, len(src))
		xorBlocksViGeneric(&generic, want, src)
		got := append([]byte(nil), src...)
		xor(&assembly, unsafe.SliceData(got), unsafe.SliceData(got), uintptr(blocks))
		if !bytes.Equal(got, want) || assembly != generic {
			t.Fatalf("%s %d blocks: batch differs", name, blocks)
		}
		for offset := uintptr(1); offset < 16; offset++ {
			var assemblyInPlace snowVState
			initialize(&assemblyInPlace, unsafe.SliceData(key), unsafe.SliceData(iv))
			inPlace, inPlaceBacking, inPlaceStart := makeGuardedSnowViUnalignedSliceAMD64(t, len(src), offset)
			copy(inPlace, src)
			xor(&assemblyInPlace, unsafe.SliceData(inPlace), unsafe.SliceData(inPlace), uintptr(blocks))
			if !bytes.Equal(inPlace, want) || assemblyInPlace != generic {
				t.Fatalf("%s %d blocks offset %d: unaligned in-place batch differs", name, blocks, offset)
			}
			assertSnowViGuardCanariesAMD64(t, inPlaceBacking, inPlaceStart, len(inPlace))

			dstOffset := offset%15 + 1
			var assemblyDisjoint snowVState
			initialize(&assemblyDisjoint, unsafe.SliceData(key), unsafe.SliceData(iv))
			unalignedSrc, srcBacking, srcStart := makeGuardedSnowViUnalignedSliceAMD64(t, len(src), offset)
			unalignedDst, dstBacking, dstStart := makeGuardedSnowViUnalignedSliceAMD64(t, len(src), dstOffset)
			copy(unalignedSrc, src)
			srcBefore := append([]byte(nil), unalignedSrc...)
			xor(&assemblyDisjoint, unsafe.SliceData(unalignedDst), unsafe.SliceData(unalignedSrc), uintptr(blocks))
			if !bytes.Equal(unalignedDst, want) || !bytes.Equal(unalignedSrc, srcBefore) || assemblyDisjoint != generic {
				t.Fatalf("%s %d blocks offsets %d/%d: unaligned disjoint batch differs", name, blocks, offset, dstOffset)
			}
			assertSnowViGuardCanariesAMD64(t, srcBacking, srcStart, len(unalignedSrc))
			assertSnowViGuardCanariesAMD64(t, dstBacking, dstStart, len(unalignedDst))
		}
	}
}

const snowViAMD64TestCanary = 0xa5

func makeGuardedSnowViUnalignedSliceAMD64(t *testing.T, length int, residue uintptr) ([]byte, []byte, int) {
	t.Helper()
	backing := bytes.Repeat([]byte{snowViAMD64TestCanary}, length+32)
	base := uintptr(unsafe.Pointer(unsafe.SliceData(backing)))
	offset := int((residue + 16 - base%16) % 16)
	slice := backing[offset : offset+length]
	if got := uintptr(unsafe.Pointer(unsafe.SliceData(slice))) % 16; got != residue {
		t.Fatalf("slice address modulo 16 = %d, want %d", got, residue)
	}
	return slice, backing, offset
}

func assertSnowViGuardCanariesAMD64(t *testing.T, backing []byte, start, length int) {
	t.Helper()
	for index, value := range backing[:start] {
		if value != snowViAMD64TestCanary {
			t.Fatalf("prefix canary %d changed", index)
		}
	}
	for index, value := range backing[start+length:] {
		if value != snowViAMD64TestCanary {
			t.Fatalf("suffix canary %d changed", index)
		}
	}
}
