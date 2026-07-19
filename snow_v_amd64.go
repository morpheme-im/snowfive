//go:build amd64 && !purego && !noasm

package snowfive

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/cpu"
)

var (
	hasAESAMD64              = cpu.X86.HasAES
	hasAVX2AMD64             = cpu.X86.HasAVX2
	hasSSSE3AMD64            = cpu.X86.HasSSSE3
	hasVAESCPUIDAMD64Feature = hasVAESCPUIDAMD64()
	hasVAESAMD64             = hasAESAMD64 && hasAVX2AMD64 && hasVAESCPUIDAMD64Feature
	selectedBackend          = selectAMD64Backend(
		hasAESAMD64,
		hasSSSE3AMD64,
		hasAVX2AMD64,
		hasVAESCPUIDAMD64Feature,
	)
)

func initializeBackend(state *snowVState, key, iv []byte) {
	switch selectedBackend {
	case snowBackendAMD64VAES:
		initStateAVX2(state, unsafe.SliceData(key), unsafe.SliceData(iv))
	case snowBackendAMD64XMM:
		initStateXMM(state, unsafe.SliceData(key), unsafe.SliceData(iv))
	case snowBackendAMD64AES:
		initializeAESAMD64(state, key, iv)
	default:
		initializeGeneric(state, key, iv)
	}
}

func xorBlocksBackend(state *snowVState, dst, src []byte) {
	switch selectedBackend {
	case snowBackendAMD64VAES:
		xorBlocksAVX2(state, unsafe.SliceData(dst), unsafe.SliceData(src), uintptr(len(src)/16))
	case snowBackendAMD64XMM:
		xorBlocksXMM(state, unsafe.SliceData(dst), unsafe.SliceData(src), uintptr(len(src)/16))
	case snowBackendAMD64AES:
		xorBlocksAESAMD64(state, dst, src)
	default:
		xorBlocksGeneric(state, dst, src)
	}
}

func initializeAESAMD64(state *snowVState, key, iv []byte) {
	loadStateGeneric(state, key, iv)
	var discarded [16]byte
	for round := range 16 {
		stepAESAMD64(state, &discarded)
		for i := range 8 {
			state.hi[i] ^= binary.LittleEndian.Uint16(discarded[2*i:])
		}
		if round == 14 {
			state.r1[0] ^= binary.LittleEndian.Uint32(key[0:4])
			state.r1[1] ^= binary.LittleEndian.Uint32(key[4:8])
			state.r1[2] ^= binary.LittleEndian.Uint32(key[8:12])
			state.r1[3] ^= binary.LittleEndian.Uint32(key[12:16])
		}
		if round == 15 {
			state.r1[0] ^= binary.LittleEndian.Uint32(key[16:20])
			state.r1[1] ^= binary.LittleEndian.Uint32(key[20:24])
			state.r1[2] ^= binary.LittleEndian.Uint32(key[24:28])
			state.r1[3] ^= binary.LittleEndian.Uint32(key[28:32])
		}
	}
}

func xorBlocksAESAMD64(state *snowVState, dst, src []byte) {
	var stream [16]byte
	for offset := 0; offset < len(src); offset += 16 {
		stepAESAMD64(state, &stream)
		for i := range 16 {
			dst[offset+i] = src[offset+i] ^ stream[i]
		}
	}
}

func stepAESAMD64(state *snowVState, out *[16]byte) {
	t10 := uint32(state.hi[8]) | uint32(state.hi[9])<<16
	t11 := uint32(state.hi[10]) | uint32(state.hi[11])<<16
	t12 := uint32(state.hi[12]) | uint32(state.hi[13])<<16
	t13 := uint32(state.hi[14]) | uint32(state.hi[15])<<16
	t20 := uint32(state.lo[0]) | uint32(state.lo[1])<<16
	t21 := uint32(state.lo[2]) | uint32(state.lo[3])<<16
	t22 := uint32(state.lo[4]) | uint32(state.lo[5])<<16
	t23 := uint32(state.lo[6]) | uint32(state.lo[7])<<16

	binary.LittleEndian.PutUint32(out[0:4], (state.r1[0]+t10)^state.r2[0])
	binary.LittleEndian.PutUint32(out[4:8], (state.r1[1]+t11)^state.r2[1])
	binary.LittleEndian.PutUint32(out[8:12], (state.r1[2]+t12)^state.r2[2])
	binary.LittleEndian.PutUint32(out[12:16], (state.r1[3]+t13)^state.r2[3])

	u0 := state.r2[0] + (state.r3[0] ^ t20)
	u1 := state.r2[1] + (state.r3[1] ^ t21)
	u2 := state.r2[2] + (state.r3[2] ^ t22)
	u3 := state.r2[3] + (state.r3[3] ^ t23)
	nextR1 := [4]uint32{
		(u0 & 0x000000ff) | (u1&0x000000ff)<<8 | (u2&0x000000ff)<<16 | (u3&0x000000ff)<<24,
		(u0>>8)&0x000000ff | (u1 & 0x0000ff00) | (u2&0x0000ff00)<<8 | (u3&0x0000ff00)<<16,
		(u0>>16)&0x000000ff | (u1>>8)&0x0000ff00 | (u2 & 0x00ff0000) | (u3&0x00ff0000)<<8,
		(u0 >> 24) | (u1>>16)&0x0000ff00 | (u2>>8)&0x00ff0000 | (u3 & 0xff000000),
	}
	var nextR2, nextR3 [4]uint32
	aesRoundPairAES(&nextR2, &nextR3, &state.r1, &state.r2)
	lfsrUpdateGeneric(state)
	state.r1 = nextR1
	state.r2 = nextR2
	state.r3 = nextR3
}

//go:noescape
func hasVAESCPUIDAMD64() bool

//go:noescape
func initStateXMM(state *snowVState, key, iv *byte)

//go:noescape
func xorBlocksXMM(state *snowVState, dst, src *byte, blocks uintptr)

//go:noescape
func initStateAVX2(state *snowVState, key, iv *byte)

//go:noescape
func xorBlocksAVX2(state *snowVState, dst, src *byte, blocks uintptr)

//go:noescape
func aesRoundPairAES(dstR2, dstR3, srcR1, srcR2 *[4]uint32)
