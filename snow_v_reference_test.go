package snowfive

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"math/rand/v2"
	"testing"
)

type referenceState struct {
	a  [16]uint16
	b  [16]uint16
	r1 [4]uint32
	r2 [4]uint32
	r3 [4]uint32
}

func initializeReference(key, iv []byte) referenceState {
	var state referenceState
	for i := range 8 {
		state.a[i] = binary.LittleEndian.Uint16(iv[2*i:])
		state.a[8+i] = binary.LittleEndian.Uint16(key[2*i:])
		state.b[8+i] = binary.LittleEndian.Uint16(key[16+2*i:])
	}
	for round := range 16 {
		z := state.step()
		for i := range 8 {
			state.a[8+i] ^= binary.LittleEndian.Uint16(z[2*i:])
		}
		if round == 14 {
			for i := range 4 {
				state.r1[i] ^= binary.LittleEndian.Uint32(key[4*i:])
			}
		}
		if round == 15 {
			for i := range 4 {
				state.r1[i] ^= binary.LittleEndian.Uint32(key[16+4*i:])
			}
		}
	}
	return state
}

func (state *referenceState) step() [16]byte {
	var out [16]byte
	for i := range 4 {
		t1 := uint32(state.b[8+2*i]) | uint32(state.b[9+2*i])<<16
		binary.LittleEndian.PutUint32(out[4*i:], (state.r1[i]+t1)^state.r2[i])
	}

	oldR1, oldR2 := state.r1, state.r2
	for i := range 4 {
		t2 := uint32(state.a[2*i]) | uint32(state.a[2*i+1])<<16
		state.r1[i] = state.r2[i] + (state.r3[i] ^ t2)
	}
	var transposed [4]uint32
	for word := range 4 {
		for source := range 4 {
			transposed[word] |= ((state.r1[source] >> (8 * word)) & 0xff) << (8 * source)
		}
	}
	state.r1 = transposed
	state.r2 = aesRoundReference(oldR1)
	state.r3 = aesRoundReference(oldR2)

	for range 8 {
		newA := referenceMulX(state.a[0], gA) ^ state.a[1] ^ referenceMulXInv(state.a[8], gAInv) ^ state.b[0]
		newB := referenceMulX(state.b[0], gB) ^ state.b[3] ^ referenceMulXInv(state.b[8], gBInv) ^ state.a[0]
		copy(state.a[:15], state.a[1:])
		copy(state.b[:15], state.b[1:])
		state.a[15] = newA
		state.b[15] = newB
	}
	return out
}

func (state referenceState) productionState() snowVState {
	var result snowVState
	copy(result.lo[:8], state.a[:8])
	copy(result.lo[8:], state.b[:8])
	copy(result.hi[:8], state.a[8:])
	copy(result.hi[8:], state.b[8:])
	result.r1, result.r2, result.r3 = state.r1, state.r2, state.r3
	return result
}

func referenceMulX(value, polynomial uint16) uint16 {
	if value&0x8000 != 0 {
		return value<<1 ^ polynomial
	}
	return value << 1
}

func referenceMulXInv(value, inverse uint16) uint16 {
	if value&1 != 0 {
		return value>>1 ^ inverse
	}
	return value >> 1
}

func aesRoundReference(words [4]uint32) [4]uint32 {
	var substituted, shifted [16]byte
	for column := range 4 {
		var encoded [4]byte
		binary.LittleEndian.PutUint32(encoded[:], words[column])
		for row := range 4 {
			substituted[4*column+row] = aesSBoxReference(encoded[row])
		}
	}
	for column := range 4 {
		for row := range 4 {
			shifted[4*column+row] = substituted[4*((column+row)&3)+row]
		}
	}
	var result [4]uint32
	for column := range 4 {
		offset := 4 * column
		a0, a1 := shifted[offset], shifted[offset+1]
		a2, a3 := shifted[offset+2], shifted[offset+3]
		total := a0 ^ a1 ^ a2 ^ a3
		mixed := [4]byte{
			a0 ^ total ^ gfXtime(a0^a1),
			a1 ^ total ^ gfXtime(a1^a2),
			a2 ^ total ^ gfXtime(a2^a3),
			a3 ^ total ^ gfXtime(a3^a0),
		}
		result[column] = binary.LittleEndian.Uint32(mixed[:])
	}
	return result
}

func aesSBoxReference(value byte) byte {
	inverse := byte(1)
	power := value
	for bit := range 8 {
		if (0xfe>>bit)&1 != 0 {
			inverse = gfMultiply(inverse, power)
		}
		power = gfMultiply(power, power)
	}
	return inverse ^ bits.RotateLeft8(inverse, 1) ^ bits.RotateLeft8(inverse, 2) ^
		bits.RotateLeft8(inverse, 3) ^ bits.RotateLeft8(inverse, 4) ^ 0x63
}

func gfMultiply(left, right byte) byte {
	var result byte
	for range 8 {
		result ^= left & byte(0-(right&1))
		left = gfXtime(left)
		right >>= 1
	}
	return result
}

func gfXtime(value byte) byte {
	return value<<1 ^ (byte(0-(value>>7)) & 0x1b)
}

func fillDeterministic(random *rand.Rand, dst []byte) {
	for offset := 0; offset < len(dst); offset += 8 {
		binary.LittleEndian.PutUint64(dst[offset:], random.Uint64())
	}
}

func TestSnowVGenericDifferential(t *testing.T) {
	random := rand.New(rand.NewPCG(0x534e4f5756, 0x20181143))
	for testCase := range 100 {
		key := make([]byte, KeySize)
		iv := make([]byte, IVSize)
		fillDeterministic(random, key)
		fillDeterministic(random, iv)
		reference := initializeReference(key, iv)
		var generic snowVState
		initializeGeneric(&generic, key, iv)
		if generic != reference.productionState() {
			t.Fatalf("case %d: state differs after initialization", testCase)
		}
		for block := range 64 {
			want := reference.step()
			var got [16]byte
			stepGeneric(&generic, &got)
			if got != want {
				t.Fatalf("case %d block %d: output differs", testCase, block)
			}
			if generic != reference.productionState() {
				t.Fatalf("case %d block %d: state differs", testCase, block)
			}
		}
	}
}

func TestSnowAESRoundPairDifferential(t *testing.T) {
	check := func(name string, first, second [4]uint32) {
		t.Helper()
		var gotFirst, gotSecond [4]uint32
		aesRoundPairGeneric(&gotFirst, &gotSecond, &first, &second)
		if want := aesRoundReference(first); gotFirst != want {
			t.Fatalf("%s: first state differs", name)
		}
		if want := aesRoundReference(second); gotSecond != want {
			t.Fatalf("%s: second state differs", name)
		}
	}
	for value := range 256 {
		word := uint32(value) * 0x01010101
		check("repeated", [4]uint32{word, word, word, word}, [4]uint32{word, word, word, word})
	}
	random := rand.New(rand.NewPCG(0x41455352, 0x2009191))
	for testCase := range 1000 {
		var first, second [16]byte
		fillDeterministic(random, first[:])
		fillDeterministic(random, second[:])
		var firstWords, secondWords [4]uint32
		for i := range 4 {
			firstWords[i] = binary.LittleEndian.Uint32(first[4*i:])
			secondWords[i] = binary.LittleEndian.Uint32(second[4*i:])
		}
		check("random", firstWords, secondWords)
		if bytes.Equal(first[:], second[:]) {
			t.Fatalf("case %d: deterministic random pair unexpectedly equal", testCase)
		}
	}
}
