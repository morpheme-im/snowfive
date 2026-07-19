package snowfive

import "encoding/binary"

const (
	snowViGA uint16 = 0x4a6d
	snowViGB uint16 = 0xcc87
)

func initializeViGeneric(state *snowVState, key, iv []byte) {
	loadStateGeneric(state, key, iv)
	var discarded [16]byte
	for round := range 16 {
		stepViGeneric(state, &discarded)
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

func xorBlocksViGeneric(state *snowVState, dst, src []byte) {
	var stream [16]byte
	for offset := 0; offset < len(src); offset += 16 {
		stepViGeneric(state, &stream)
		for i := range 16 {
			dst[offset+i] = src[offset+i] ^ stream[i]
		}
	}
}

func stepViGeneric(state *snowVState, out *[16]byte) {
	t10 := uint32(state.hi[8]) | uint32(state.hi[9])<<16
	t11 := uint32(state.hi[10]) | uint32(state.hi[11])<<16
	t12 := uint32(state.hi[12]) | uint32(state.hi[13])<<16
	t13 := uint32(state.hi[14]) | uint32(state.hi[15])<<16
	t20 := uint32(state.hi[0]) | uint32(state.hi[1])<<16
	t21 := uint32(state.hi[2]) | uint32(state.hi[3])<<16
	t22 := uint32(state.hi[4]) | uint32(state.hi[5])<<16
	t23 := uint32(state.hi[6]) | uint32(state.hi[7])<<16

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
	lfsrUpdateViGeneric(state)
	state.r1 = nextR1
	state.r2 = nextR2
	state.r3 = nextR3
}

func lfsrUpdateViGeneric(state *snowVState) {
	newA0 := mulX(state.lo[0], snowViGA) ^ state.lo[8] ^ state.lo[7]
	newA1 := mulX(state.lo[1], snowViGA) ^ state.lo[9] ^ state.hi[0]
	newA2 := mulX(state.lo[2], snowViGA) ^ state.lo[10] ^ state.hi[1]
	newA3 := mulX(state.lo[3], snowViGA) ^ state.lo[11] ^ state.hi[2]
	newA4 := mulX(state.lo[4], snowViGA) ^ state.lo[12] ^ state.hi[3]
	newA5 := mulX(state.lo[5], snowViGA) ^ state.lo[13] ^ state.hi[4]
	newA6 := mulX(state.lo[6], snowViGA) ^ state.lo[14] ^ state.hi[5]
	newA7 := mulX(state.lo[7], snowViGA) ^ state.lo[15] ^ state.hi[6]
	newB0 := mulX(state.lo[8], snowViGB) ^ state.lo[0] ^ state.hi[8]
	newB1 := mulX(state.lo[9], snowViGB) ^ state.lo[1] ^ state.hi[9]
	newB2 := mulX(state.lo[10], snowViGB) ^ state.lo[2] ^ state.hi[10]
	newB3 := mulX(state.lo[11], snowViGB) ^ state.lo[3] ^ state.hi[11]
	newB4 := mulX(state.lo[12], snowViGB) ^ state.lo[4] ^ state.hi[12]
	newB5 := mulX(state.lo[13], snowViGB) ^ state.lo[5] ^ state.hi[13]
	newB6 := mulX(state.lo[14], snowViGB) ^ state.lo[6] ^ state.hi[14]
	newB7 := mulX(state.lo[15], snowViGB) ^ state.lo[7] ^ state.hi[15]

	state.lo = state.hi
	state.hi = [16]uint16{
		newA0, newA1, newA2, newA3, newA4, newA5, newA6, newA7,
		newB0, newB1, newB2, newB3, newB4, newB5, newB6, newB7,
	}
}
