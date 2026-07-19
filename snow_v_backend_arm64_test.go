//go:build arm64 && !purego && !noasm

package snowfive

import (
	"bytes"
	"math/rand/v2"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/cpu"
)

func TestSnowVBackendDifferentialARM64(t *testing.T) {
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
		initializeGeneric(&generic, key, iv)
		initStateARM64(&assembly, unsafe.SliceData(key), unsafe.SliceData(iv))
		if assembly != generic {
			t.Fatalf("case %d: state differs after initialization", testCase)
		}
		for block := range 64 {
			var src, want, got [16]byte
			fillDeterministic(random, src[:])
			xorBlocksGeneric(&generic, want[:], src[:])
			xorBlocksARM64(&assembly, unsafe.SliceData(got[:]), unsafe.SliceData(src[:]), 1)
			if got != want {
				t.Fatalf("case %d block %d: output differs", testCase, block)
			}
			if assembly != generic {
				t.Fatalf("case %d block %d: state differs", testCase, block)
			}
		}
	}
}

func TestSnowVBackendBatchesARM64(t *testing.T) {
	if !hasARM64AES {
		t.Skip("ARM64 AES/ASIMD unavailable")
	}
	implementations := [...]struct {
		name      string
		available bool
		xorBlocks func(*snowVState, *byte, *byte, uintptr)
	}{
		{name: "NEON+AES", available: hasARM64AES, xorBlocks: xorBlocksARM64},
		{name: "NEON+AES+SHA3", available: hasARM64SHA3, xorBlocks: xorBlocksARM64SHA3},
	}
	for _, implementation := range implementations {
		if !implementation.available {
			continue
		}
		t.Run(implementation.name, func(t *testing.T) {
			testBackendBatchesARM64(t, implementation.xorBlocks)
		})
	}
}

func testBackendBatchesARM64(t *testing.T, xorBlocks func(*snowVState, *byte, *byte, uintptr)) {
	random := rand.New(rand.NewPCG(0x4241544348, 0x41524d64))
	key := makeUnalignedSlice(t, KeySize, 1)
	iv := makeUnalignedSlice(t, IVSize, 3)
	fillDeterministic(random, key)
	fillDeterministic(random, iv)
	for blocks := 1; blocks <= 9; blocks++ {
		src := make([]byte, 16*blocks)
		fillDeterministic(random, src)
		var generic, assembly snowVState
		initializeGeneric(&generic, key, iv)
		initStateARM64(&assembly, unsafe.SliceData(key), unsafe.SliceData(iv))
		want := make([]byte, len(src))
		xorBlocksGeneric(&generic, want, src)
		got := append([]byte(nil), src...)
		xorBlocks(&assembly, unsafe.SliceData(got), unsafe.SliceData(got), uintptr(blocks))
		if !bytes.Equal(got, want) {
			t.Fatalf("%d blocks: in-place output differs", blocks)
		}
		if assembly != generic {
			t.Fatalf("%d blocks: final state differs", blocks)
		}
		var genericDisjoint, assemblyDisjoint snowVState
		initializeGeneric(&genericDisjoint, key, iv)
		initStateARM64(&assemblyDisjoint, unsafe.SliceData(key), unsafe.SliceData(iv))
		wantDisjoint := make([]byte, len(src))
		xorBlocksGeneric(&genericDisjoint, wantDisjoint, src)
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
			initStateARM64(&assemblyInPlace, unsafe.SliceData(key), unsafe.SliceData(iv))
			inPlace, inPlaceBacking, inPlaceStart := makeGuardedUnalignedSlice(t, len(src), offset)
			copy(inPlace, src)
			xorBlocks(&assemblyInPlace, unsafe.SliceData(inPlace), unsafe.SliceData(inPlace), uintptr(blocks))
			if !bytes.Equal(inPlace, want) {
				t.Fatalf("%d blocks offset %d: unaligned in-place output differs", blocks, offset)
			}
			if assemblyInPlace != generic {
				t.Fatalf("%d blocks offset %d: unaligned in-place final state differs", blocks, offset)
			}
			assertGuardCanaries(t, inPlaceBacking, inPlaceStart, len(inPlace))

			dstOffset := offset%15 + 1
			var assemblyDisjointUnaligned snowVState
			initStateARM64(&assemblyDisjointUnaligned, unsafe.SliceData(key), unsafe.SliceData(iv))
			unalignedSrc, srcBacking, srcStart := makeGuardedUnalignedSlice(t, len(src), offset)
			unalignedDst, dstBacking, dstStart := makeGuardedUnalignedSlice(t, len(src), dstOffset)
			copy(unalignedSrc, src)
			srcBefore := append([]byte(nil), unalignedSrc...)
			xorBlocks(&assemblyDisjointUnaligned, unsafe.SliceData(unalignedDst), unsafe.SliceData(unalignedSrc), uintptr(blocks))
			if !bytes.Equal(unalignedDst, want) || !bytes.Equal(unalignedSrc, srcBefore) {
				t.Fatalf("%d blocks offsets %d/%d: unaligned disjoint output or source differs", blocks, offset, dstOffset)
			}
			if assemblyDisjointUnaligned != generic {
				t.Fatalf("%d blocks offsets %d/%d: unaligned disjoint final state differs", blocks, offset, dstOffset)
			}
			assertGuardCanaries(t, srcBacking, srcStart, len(unalignedSrc))
			assertGuardCanaries(t, dstBacking, dstStart, len(unalignedDst))
		}
	}
}

const arm64TestCanary = 0xa5

func makeGuardedUnalignedSlice(t *testing.T, length int, residue uintptr) ([]byte, []byte, int) {
	t.Helper()
	backing := bytes.Repeat([]byte{arm64TestCanary}, length+32)
	base := uintptr(unsafe.Pointer(unsafe.SliceData(backing)))
	offset := int((residue + 16 - base%16) % 16)
	slice := backing[offset : offset+length]
	if got := uintptr(unsafe.Pointer(unsafe.SliceData(slice))) % 16; got != residue {
		t.Fatalf("slice address modulo 16 = %d, want %d", got, residue)
	}
	return slice, backing, offset
}

func assertGuardCanaries(t *testing.T, backing []byte, start, length int) {
	t.Helper()
	for index, value := range backing[:start] {
		if value != arm64TestCanary {
			t.Fatalf("prefix canary %d changed", index)
		}
	}
	for index, value := range backing[start+length:] {
		if value != arm64TestCanary {
			t.Fatalf("suffix canary %d changed", index)
		}
	}
}

func TestSnowExpectedRuntimeBackend(t *testing.T) {
	profile := os.Getenv("SNOWFIVE_EXPECT_PROFILE")
	if profile == "" {
		return
	}
	disabled := validateExpectedDisabled(
		t,
		profile,
		os.Getenv("SNOWFIVE_EXPECT_DISABLED"),
		[]string{"asimd", "aes", "sha3"},
	)
	if disabled["asimd"] && cpu.ARM64.HasASIMD {
		t.Fatal("GODEBUG did not disable cpu.ARM64.HasASIMD")
	}
	if disabled["aes"] && cpu.ARM64.HasAES {
		t.Fatal("GODEBUG did not disable cpu.ARM64.HasAES")
	}
	if disabled["sha3"] && cpu.ARM64.HasSHA3 {
		t.Fatal("GODEBUG did not disable cpu.ARM64.HasSHA3")
	}
	expected := selectARM64Backend(cpu.ARM64.HasASIMD, cpu.ARM64.HasAES, cpu.ARM64.HasSHA3)
	if selectedBackend != expected {
		t.Fatalf("selected backend = %d, want %d", selectedBackend, expected)
	}
	t.Logf(
		"profile=%s ASIMD=%t AES=%t SHA3=%t backend=%d",
		profile,
		cpu.ARM64.HasASIMD,
		cpu.ARM64.HasAES,
		cpu.ARM64.HasSHA3,
		selectedBackend,
	)
	exerciseSelectedBackendPublishedBlocks(t)
}
