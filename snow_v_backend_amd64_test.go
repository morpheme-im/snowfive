//go:build amd64 && !purego && !noasm

package snowfive

import (
	"bytes"
	"math/rand/v2"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/cpu"
)

func TestSnowVAESRoundPairAES(t *testing.T) {
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

func TestSnowVBackendDifferentialAMD64(t *testing.T) {
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
		initializeGeneric(&generic, key, iv)
		initializeAESAMD64(&aesOnly, key, iv)
		if aesOnly != generic {
			t.Fatalf("case %d: AES-only initialization differs", testCase)
		}
		for block := range 64 {
			var src, want, got [16]byte
			fillDeterministic(random, src[:])
			xorBlocksGeneric(&generic, want[:], src[:])
			xorBlocksAESAMD64(&aesOnly, got[:], src[:])
			if got != want || aesOnly != generic {
				t.Fatalf("case %d block %d: AES-only backend differs", testCase, block)
			}
		}
	}

	if hasSSSE3AMD64 {
		testBackendDifferentialTierAMD64(t, "XMM", 0x584d4d32, initStateXMM, xorBlocksXMM)
	}
	if hasVAESAMD64 {
		testBackendDifferentialTierAMD64(t, "VAES", 0x56414553, initStateAVX2, xorBlocksAVX2)
	}
}

type amd64StateInitializer func(*snowVState, *byte, *byte)

type amd64BlockXOR func(*snowVState, *byte, *byte, uintptr)

func testBackendDifferentialTierAMD64(t *testing.T, name string, seed uint64, initialize amd64StateInitializer, xor amd64BlockXOR) {
	t.Helper()
	random := rand.New(rand.NewPCG(seed, 0x20181143))
	for testCase := range 100 {
		key := make([]byte, KeySize)
		iv := make([]byte, IVSize)
		fillDeterministic(random, key)
		fillDeterministic(random, iv)
		var generic, assembly snowVState
		initializeGeneric(&generic, key, iv)
		initialize(&assembly, unsafe.SliceData(key), unsafe.SliceData(iv))
		if assembly != generic {
			t.Fatalf("%s case %d: initialization differs", name, testCase)
		}
		for block := range 64 {
			var src, want, got [16]byte
			fillDeterministic(random, src[:])
			xorBlocksGeneric(&generic, want[:], src[:])
			xor(&assembly, unsafe.SliceData(got[:]), unsafe.SliceData(src[:]), 1)
			if got != want || assembly != generic {
				t.Fatalf("%s case %d block %d: backend differs", name, testCase, block)
			}
		}
	}
}

func TestSnowVBackendBatchesAMD64(t *testing.T) {
	ran := false
	if hasAESAMD64 && hasSSSE3AMD64 {
		ran = true
		t.Run("XMM", func(t *testing.T) {
			testBackendBatchesTierAMD64(t, "XMM", initStateXMM, xorBlocksXMM)
		})
	}
	if hasVAESAMD64 {
		ran = true
		t.Run("VAES", func(t *testing.T) {
			testBackendBatchesTierAMD64(t, "VAES", initStateAVX2, xorBlocksAVX2)
		})
	}
	if !ran {
		t.Skip("AES-NI/SSSE3 unavailable")
	}
}

func testBackendBatchesTierAMD64(t *testing.T, name string, initialize amd64StateInitializer, xor amd64BlockXOR) {
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
		initializeGeneric(&generic, key, iv)
		initialize(&assembly, unsafe.SliceData(key), unsafe.SliceData(iv))
		want := make([]byte, len(src))
		xorBlocksGeneric(&generic, want, src)
		got := append([]byte(nil), src...)
		xor(&assembly, unsafe.SliceData(got), unsafe.SliceData(got), uintptr(blocks))
		if !bytes.Equal(got, want) || assembly != generic {
			t.Fatalf("%s %d blocks: batch differs", name, blocks)
		}
		for offset := uintptr(1); offset < 16; offset++ {
			var assemblyInPlace snowVState
			initialize(&assemblyInPlace, unsafe.SliceData(key), unsafe.SliceData(iv))
			inPlace, inPlaceBacking, inPlaceStart := makeGuardedUnalignedSliceAMD64(t, len(src), offset)
			copy(inPlace, src)
			xor(&assemblyInPlace, unsafe.SliceData(inPlace), unsafe.SliceData(inPlace), uintptr(blocks))
			if !bytes.Equal(inPlace, want) || assemblyInPlace != generic {
				t.Fatalf("%s %d blocks offset %d: unaligned in-place batch differs", name, blocks, offset)
			}
			assertGuardCanariesAMD64(t, inPlaceBacking, inPlaceStart, len(inPlace))

			dstOffset := offset%15 + 1
			var assemblyDisjoint snowVState
			initialize(&assemblyDisjoint, unsafe.SliceData(key), unsafe.SliceData(iv))
			unalignedSrc, srcBacking, srcStart := makeGuardedUnalignedSliceAMD64(t, len(src), offset)
			unalignedDst, dstBacking, dstStart := makeGuardedUnalignedSliceAMD64(t, len(src), dstOffset)
			copy(unalignedSrc, src)
			srcBefore := append([]byte(nil), unalignedSrc...)
			xor(&assemblyDisjoint, unsafe.SliceData(unalignedDst), unsafe.SliceData(unalignedSrc), uintptr(blocks))
			if !bytes.Equal(unalignedDst, want) || !bytes.Equal(unalignedSrc, srcBefore) || assemblyDisjoint != generic {
				t.Fatalf("%s %d blocks offsets %d/%d: unaligned disjoint batch differs", name, blocks, offset, dstOffset)
			}
			assertGuardCanariesAMD64(t, srcBacking, srcStart, len(unalignedSrc))
			assertGuardCanariesAMD64(t, dstBacking, dstStart, len(unalignedDst))
		}
	}
}

const amd64TestCanary = 0xa5

func makeGuardedUnalignedSliceAMD64(t *testing.T, length int, residue uintptr) ([]byte, []byte, int) {
	t.Helper()
	backing := bytes.Repeat([]byte{amd64TestCanary}, length+32)
	base := uintptr(unsafe.Pointer(unsafe.SliceData(backing)))
	offset := int((residue + 16 - base%16) % 16)
	slice := backing[offset : offset+length]
	if got := uintptr(unsafe.Pointer(unsafe.SliceData(slice))) % 16; got != residue {
		t.Fatalf("slice address modulo 16 = %d, want %d", got, residue)
	}
	return slice, backing, offset
}

func assertGuardCanariesAMD64(t *testing.T, backing []byte, start, length int) {
	t.Helper()
	for index, value := range backing[:start] {
		if value != amd64TestCanary {
			t.Fatalf("prefix canary %d changed", index)
		}
	}
	for index, value := range backing[start+length:] {
		if value != amd64TestCanary {
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
		[]string{"aes", "ssse3", "avx2"},
	)
	if disabled["aes"] && cpu.X86.HasAES {
		t.Fatal("GODEBUG did not disable cpu.X86.HasAES")
	}
	if disabled["ssse3"] && cpu.X86.HasSSSE3 {
		t.Fatal("GODEBUG did not disable cpu.X86.HasSSSE3")
	}
	if disabled["avx2"] && cpu.X86.HasAVX2 {
		t.Fatal("GODEBUG did not disable cpu.X86.HasAVX2")
	}
	expected := selectAMD64Backend(
		cpu.X86.HasAES,
		cpu.X86.HasSSSE3,
		cpu.X86.HasAVX2,
		hasVAESCPUIDAMD64Feature,
	)
	if selectedBackend != expected {
		t.Fatalf("selected backend = %d, want %d", selectedBackend, expected)
	}
	t.Logf(
		"profile=%s AES=%t SSSE3=%t AVX2=%t VAES=%t backend=%d",
		profile,
		cpu.X86.HasAES,
		cpu.X86.HasSSSE3,
		cpu.X86.HasAVX2,
		hasVAESCPUIDAMD64Feature,
		selectedBackend,
	)
	exerciseSelectedBackendPublishedBlocks(t)
}
