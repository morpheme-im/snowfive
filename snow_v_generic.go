package snowfive

import "encoding/binary"

const (
	gA    uint16 = 0x990f
	gAInv uint16 = 0xcc87
	gB    uint16 = 0xc963
	gBInv uint16 = 0xe4b1
)

var sigma = [16]byte{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}

func mulX(v, c uint16) uint16 {
	return (v << 1) ^ ((0 - (v >> 15)) & c)
}

func mulXInv(v, d uint16) uint16 {
	return (v >> 1) ^ ((0 - (v & 1)) & d)
}

func loadStateGeneric(state *snowVState, key, iv []byte) {
	*state = snowVState{}
	for i := range 8 {
		state.lo[i] = binary.LittleEndian.Uint16(iv[2*i:])
		state.hi[i] = binary.LittleEndian.Uint16(key[2*i:])
		state.hi[8+i] = binary.LittleEndian.Uint16(key[16+2*i:])
	}
}

func initializeGeneric(state *snowVState, key, iv []byte) {
	loadStateGeneric(state, key, iv)
	var discarded [16]byte
	for round := range 16 {
		stepGeneric(state, &discarded)
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

func xorBlocksGeneric(state *snowVState, dst, src []byte) {
	var stream [16]byte
	for offset := 0; offset < len(src); offset += 16 {
		stepGeneric(state, &stream)
		for i := range 16 {
			dst[offset+i] = src[offset+i] ^ stream[i]
		}
	}
}

func stepGeneric(state *snowVState, out *[16]byte) {
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
	aesRoundPairGeneric(&nextR2, &nextR3, &state.r1, &state.r2)
	lfsrUpdateGeneric(state)
	state.r1 = nextR1
	state.r2 = nextR2
	state.r3 = nextR3
}

func lfsrUpdateGeneric(state *snowVState) {
	newA0 := mulX(state.lo[0], gA) ^ state.lo[1] ^ mulXInv(state.hi[0], gAInv) ^ state.lo[8]
	newA1 := mulX(state.lo[1], gA) ^ state.lo[2] ^ mulXInv(state.hi[1], gAInv) ^ state.lo[9]
	newA2 := mulX(state.lo[2], gA) ^ state.lo[3] ^ mulXInv(state.hi[2], gAInv) ^ state.lo[10]
	newA3 := mulX(state.lo[3], gA) ^ state.lo[4] ^ mulXInv(state.hi[3], gAInv) ^ state.lo[11]
	newA4 := mulX(state.lo[4], gA) ^ state.lo[5] ^ mulXInv(state.hi[4], gAInv) ^ state.lo[12]
	newA5 := mulX(state.lo[5], gA) ^ state.lo[6] ^ mulXInv(state.hi[5], gAInv) ^ state.lo[13]
	newA6 := mulX(state.lo[6], gA) ^ state.lo[7] ^ mulXInv(state.hi[6], gAInv) ^ state.lo[14]
	newA7 := mulX(state.lo[7], gA) ^ state.hi[0] ^ mulXInv(state.hi[7], gAInv) ^ state.lo[15]
	newB0 := mulX(state.lo[8], gB) ^ state.lo[11] ^ mulXInv(state.hi[8], gBInv) ^ state.lo[0]
	newB1 := mulX(state.lo[9], gB) ^ state.lo[12] ^ mulXInv(state.hi[9], gBInv) ^ state.lo[1]
	newB2 := mulX(state.lo[10], gB) ^ state.lo[13] ^ mulXInv(state.hi[10], gBInv) ^ state.lo[2]
	newB3 := mulX(state.lo[11], gB) ^ state.lo[14] ^ mulXInv(state.hi[11], gBInv) ^ state.lo[3]
	newB4 := mulX(state.lo[12], gB) ^ state.lo[15] ^ mulXInv(state.hi[12], gBInv) ^ state.lo[4]
	newB5 := mulX(state.lo[13], gB) ^ state.hi[8] ^ mulXInv(state.hi[13], gBInv) ^ state.lo[5]
	newB6 := mulX(state.lo[14], gB) ^ state.hi[9] ^ mulXInv(state.hi[14], gBInv) ^ state.lo[6]
	newB7 := mulX(state.lo[15], gB) ^ state.hi[10] ^ mulXInv(state.hi[15], gBInv) ^ state.lo[7]

	state.lo = state.hi
	state.hi = [16]uint16{
		newA0, newA1, newA2, newA3, newA4, newA5, newA6, newA7,
		newB0, newB1, newB2, newB3, newB4, newB5, newB6, newB7,
	}
}
