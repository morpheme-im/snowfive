package snowfive

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

type snowViReferenceState struct {
	a  [16]uint16
	b  [16]uint16
	r1 [4]uint32
	r2 [4]uint32
	r3 [4]uint32
}

func loadSnowViReference(key, iv []byte) snowViReferenceState {
	var state snowViReferenceState
	for i := range 8 {
		state.a[i] = binary.LittleEndian.Uint16(iv[2*i:])
		state.a[8+i] = binary.LittleEndian.Uint16(key[2*i:])
		state.b[8+i] = binary.LittleEndian.Uint16(key[16+2*i:])
	}
	return state
}

func initializeSnowViReference(key, iv []byte) snowViReferenceState {
	state := loadSnowViReference(key, iv)
	for round := range 16 {
		z := state.step()
		for i := range 8 {
			state.a[8+i] ^= binary.LittleEndian.Uint16(z[2*i:])
		}
		state.injectInitializationKey(round, key)
	}
	return state
}

func (state *snowViReferenceState) injectInitializationKey(round int, key []byte) {
	switch round {
	case 14:
		for i := range 4 {
			state.r1[i] ^= binary.LittleEndian.Uint32(key[4*i:])
		}
	case 15:
		for i := range 4 {
			state.r1[i] ^= binary.LittleEndian.Uint32(key[16+4*i:])
		}
	}
}

func (state *snowViReferenceState) step() [16]byte {
	var out [16]byte
	for i := range 4 {
		t1 := uint32(state.b[8+2*i]) | uint32(state.b[9+2*i])<<16
		binary.LittleEndian.PutUint32(out[4*i:], (state.r1[i]+t1)^state.r2[i])
	}

	oldR1, oldR2 := state.r1, state.r2
	for i := range 4 {
		t2 := uint32(state.a[8+2*i]) | uint32(state.a[9+2*i])<<16
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
		newA := referenceMulX(state.a[0], snowViGA) ^ state.b[0] ^ state.a[7]
		newB := referenceMulX(state.b[0], snowViGB) ^ state.a[0] ^ state.b[8]
		copy(state.a[:15], state.a[1:])
		copy(state.b[:15], state.b[1:])
		state.a[15] = newA
		state.b[15] = newB
	}
	return out
}

func (state snowViReferenceState) productionState() snowVState {
	var result snowVState
	copy(result.lo[:8], state.a[:8])
	copy(result.lo[8:], state.b[:8])
	copy(result.hi[:8], state.a[8:])
	copy(result.hi[8:], state.b[8:])
	result.r1, result.r2, result.r3 = state.r1, state.r2, state.r3
	return result
}

func TestSnowViBackendDifferential(t *testing.T) {
	random := rand.New(rand.NewPCG(0x534e4f575649, 0x34483003467829))
	for testCase := range 100 {
		key := make([]byte, KeySize)
		iv := make([]byte, IVSize)
		fillDeterministic(random, key)
		fillDeterministic(random, iv)

		reference := loadSnowViReference(key, iv)
		var generic snowVState
		loadStateGeneric(&generic, key, iv)
		for round := range 16 {
			want := reference.step()
			var got [16]byte
			stepViGeneric(&generic, &got)
			if got != want {
				t.Fatalf("case %d initialization round %d: output differs", testCase, round+1)
			}
			for i := range 8 {
				word := binary.LittleEndian.Uint16(got[2*i:])
				generic.hi[i] ^= word
				reference.a[8+i] ^= word
			}
			if round == 14 {
				for i := range 4 {
					generic.r1[i] ^= binary.LittleEndian.Uint32(key[4*i:])
				}
			}
			if round == 15 {
				for i := range 4 {
					generic.r1[i] ^= binary.LittleEndian.Uint32(key[16+4*i:])
				}
			}
			reference.injectInitializationKey(round, key)
			if generic != reference.productionState() {
				t.Fatalf("case %d initialization round %d: state differs", testCase, round+1)
			}
		}

		initializedReference := initializeSnowViReference(key, iv)
		var initializedGeneric, backend snowVState
		initializeViGeneric(&initializedGeneric, key, iv)
		initializeViBackend(&backend, key, iv)
		if initializedReference.productionState() != initializedGeneric || backend != initializedGeneric {
			t.Fatalf("case %d: initialization differs", testCase)
		}

		for block := range 64 {
			want := reference.step()
			var got, backendOutput [16]byte
			stepViGeneric(&generic, &got)
			xorBlocksViBackend(&backend, backendOutput[:], backendOutput[:])
			if got != want || backendOutput != want {
				t.Fatalf("case %d block %d: output differs", testCase, block)
			}
			wantState := reference.productionState()
			if generic != wantState || backend != wantState {
				t.Fatalf("case %d block %d: state differs", testCase, block)
			}
		}
	}
}

func TestSnowViRandomizedStreamingAgainstReference(t *testing.T) {
	random := rand.New(rand.NewPCG(0x53545245414d, 0x5649524546))
	for testCase := range 100 {
		key := make([]byte, KeySize)
		iv := make([]byte, IVSize)
		fillDeterministic(random, key)
		fillDeterministic(random, iv)

		plaintext := make([]byte, random.IntN(4097))
		for index := range plaintext {
			plaintext[index] = byte(random.Uint32())
		}
		plaintextBefore := append([]byte(nil), plaintext...)
		reference := initializeSnowViReference(key, iv)
		want := make([]byte, len(plaintext))
		for offset := 0; offset < len(plaintext); offset += 16 {
			block := reference.step()
			for index := range min(16, len(plaintext)-offset) {
				want[offset+index] = plaintext[offset+index] ^ block[index]
			}
		}

		stream, err := NewSnowViCipher(key, iv)
		if err != nil {
			t.Fatalf("case %d: constructor: %v", testCase, err)
		}
		got := make([]byte, len(plaintext))
		for offset, chunkIndex := 0, 0; offset < len(plaintext); chunkIndex++ {
			size := min(1+random.IntN(64), len(plaintext)-offset)
			if chunkIndex%2 == 0 {
				copy(got[offset:offset+size], plaintext[offset:offset+size])
				stream.XORKeyStream(got[offset:offset+size], got[offset:offset+size])
			} else {
				stream.XORKeyStream(got[offset:offset+size], plaintext[offset:offset+size])
			}
			offset += size
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d: randomized chunk stream differs", testCase)
		}
		if !bytes.Equal(plaintext, plaintextBefore) {
			t.Fatalf("case %d: disjoint source changed", testCase)
		}
	}
}
