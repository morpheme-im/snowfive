//go:build arm64 && !purego && !noasm

package snowfive

import (
	"bytes"
	"math/rand/v2"
	"testing"
	"unsafe"
)

func TestSnowViDirectBackendDifferentialARM64(t *testing.T) {
	if !hasARM64AES {
		t.Skip("ARM64 AES/ASIMD unavailable")
	}
	random := rand.New(rand.NewPCG(0x41524d3634, 0x20181143))
	for testCase := range 100 {
		key := make([]byte, KeySize)
		iv := make([]byte, IVSize)
		fillDeterministic(random, key)
		fillDeterministic(random, iv)
		var generic, assembly snowVState
		initializeViGeneric(&generic, key, iv)
		initStateViARM64(&assembly, unsafe.SliceData(key), unsafe.SliceData(iv))
		if assembly != generic {
			t.Fatalf("case %d: state differs after initialization", testCase)
		}
		for block := range 64 {
			var src, want, got [16]byte
			fillDeterministic(random, src[:])
			xorBlocksViGeneric(&generic, want[:], src[:])
			xorBlocksViARM64(&assembly, unsafe.SliceData(got[:]), unsafe.SliceData(src[:]), 1)
			if got != want {
				t.Fatalf("case %d block %d: output differs", testCase, block)
			}
			if assembly != generic {
				t.Fatalf("case %d block %d: state differs", testCase, block)
			}
		}
	}
}

func TestSnowViDirectBackendBatchesARM64(t *testing.T) {
	if !hasARM64AES {
		t.Skip("ARM64 AES/ASIMD unavailable")
	}
	implementations := [...]struct {
		name      string
		available bool
		xorBlocks func(*snowVState, *byte, *byte, uintptr)
	}{
		{name: "NEON+AES", available: hasARM64AES, xorBlocks: xorBlocksViARM64},
		{name: "NEON+AES+SHA3", available: hasARM64SHA3, xorBlocks: xorBlocksViARM64SHA3},
	}
	for _, implementation := range implementations {
		if !implementation.available {
			continue
		}
		t.Run(implementation.name, func(t *testing.T) {
			testSnowViBackendBatchesARM64(t, implementation.xorBlocks)
		})
	}
}

func testSnowViBackendBatchesARM64(t *testing.T, xorBlocks func(*snowVState, *byte, *byte, uintptr)) {
	random := rand.New(rand.NewPCG(0x4241544348, 0x41524d64))
	key := makeUnalignedSlice(t, KeySize, 1)
	iv := makeUnalignedSlice(t, IVSize, 3)
	fillDeterministic(random, key)
	fillDeterministic(random, iv)
	for blocks := 1; blocks <= 33; blocks++ {
		src := make([]byte, 16*blocks)
		fillDeterministic(random, src)
		var generic, assembly snowVState
		initializeViGeneric(&generic, key, iv)
		initStateViARM64(&assembly, unsafe.SliceData(key), unsafe.SliceData(iv))
		want := make([]byte, len(src))
		xorBlocksViGeneric(&generic, want, src)
		got := append([]byte(nil), src...)
		xorBlocks(&assembly, unsafe.SliceData(got), unsafe.SliceData(got), uintptr(blocks))
		if !bytes.Equal(got, want) {
			t.Fatalf("%d blocks: in-place output differs", blocks)
		}
		if assembly != generic {
			t.Fatalf("%d blocks: final state differs", blocks)
		}
		var genericDisjoint, assemblyDisjoint snowVState
		initializeViGeneric(&genericDisjoint, key, iv)
		initStateViARM64(&assemblyDisjoint, unsafe.SliceData(key), unsafe.SliceData(iv))
		wantDisjoint := make([]byte, len(src))
		xorBlocksViGeneric(&genericDisjoint, wantDisjoint, src)
		gotDisjoint := make([]byte, len(src))
		xorBlocks(&assemblyDisjoint, unsafe.SliceData(gotDisjoint), unsafe.SliceData(src), uintptr(blocks))
		if !bytes.Equal(gotDisjoint, wantDisjoint) {
			t.Fatalf("%d blocks: disjoint output differs", blocks)
		}
		if assemblyDisjoint != genericDisjoint {
			t.Fatalf("%d blocks: disjoint final state differs", blocks)
		}

		for offset := uintptr(1); offset < 16; offset++ {
			var assemblyInPlace snowVState
			initStateViARM64(&assemblyInPlace, unsafe.SliceData(key), unsafe.SliceData(iv))
			inPlace, inPlaceBacking, inPlaceStart := makeGuardedSnowViUnalignedSliceARM64(t, len(src), offset)
			copy(inPlace, src)
			xorBlocks(&assemblyInPlace, unsafe.SliceData(inPlace), unsafe.SliceData(inPlace), uintptr(blocks))
			if !bytes.Equal(inPlace, want) {
				t.Fatalf("%d blocks offset %d: unaligned in-place output differs", blocks, offset)
			}
			if assemblyInPlace != generic {
				t.Fatalf("%d blocks offset %d: unaligned in-place final state differs", blocks, offset)
			}
			assertSnowViGuardCanariesARM64(t, inPlaceBacking, inPlaceStart, len(inPlace))

			dstOffset := offset%15 + 1
			var assemblyDisjointUnaligned snowVState
			initStateViARM64(&assemblyDisjointUnaligned, unsafe.SliceData(key), unsafe.SliceData(iv))
			unalignedSrc, srcBacking, srcStart := makeGuardedSnowViUnalignedSliceARM64(t, len(src), offset)
			unalignedDst, dstBacking, dstStart := makeGuardedSnowViUnalignedSliceARM64(t, len(src), dstOffset)
			copy(unalignedSrc, src)
			srcBefore := append([]byte(nil), unalignedSrc...)
			xorBlocks(&assemblyDisjointUnaligned, unsafe.SliceData(unalignedDst), unsafe.SliceData(unalignedSrc), uintptr(blocks))
			if !bytes.Equal(unalignedDst, want) || !bytes.Equal(unalignedSrc, srcBefore) {
				t.Fatalf("%d blocks offsets %d/%d: unaligned disjoint output or source differs", blocks, offset, dstOffset)
			}
			if assemblyDisjointUnaligned != generic {
				t.Fatalf("%d blocks offsets %d/%d: unaligned disjoint final state differs", blocks, offset, dstOffset)
			}
			assertSnowViGuardCanariesARM64(t, srcBacking, srcStart, len(unalignedSrc))
			assertSnowViGuardCanariesARM64(t, dstBacking, dstStart, len(unalignedDst))
		}
	}
}

const snowViARM64TestCanary = 0xa5

func makeGuardedSnowViUnalignedSliceARM64(t *testing.T, length int, residue uintptr) ([]byte, []byte, int) {
	t.Helper()
	backing := bytes.Repeat([]byte{snowViARM64TestCanary}, length+32)
	base := uintptr(unsafe.Pointer(unsafe.SliceData(backing)))
	offset := int((residue + 16 - base%16) % 16)
	slice := backing[offset : offset+length]
	if got := uintptr(unsafe.Pointer(unsafe.SliceData(slice))) % 16; got != residue {
		t.Fatalf("slice address modulo 16 = %d, want %d", got, residue)
	}
	return slice, backing, offset
}

func assertSnowViGuardCanariesARM64(t *testing.T, backing []byte, start, length int) {
	t.Helper()
	for index, value := range backing[:start] {
		if value != snowViARM64TestCanary {
			t.Fatalf("prefix canary %d changed", index)
		}
	}
	for index, value := range backing[start+length:] {
		if value != snowViARM64TestCanary {
			t.Fatalf("suffix canary %d changed", index)
		}
	}
}
