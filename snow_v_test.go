package snowfive

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return decoded
}

func TestSnowVPublishedVectors(t *testing.T) {
	tests := []struct {
		name string
		key  string
		iv   string
		want string
	}{
		{
			name: "zero",
			key:  "0000000000000000000000000000000000000000000000000000000000000000",
			iv:   "00000000000000000000000000000000",
			want: "69ca6daf9ae3b72db134a85a837e419dec08aad39d7b0f009b60b28c534300ed84abf594fb08a7f1f3a2df18e617683b481fa378079dcf04db53b5d629a9eb9d031c159dccd0a50c4d5dbf5115d87039c0d03ca1370c19400347a0b4d2e9dbe5cbca608214a26582cf680916b3451321954fdf3084af02f6a8e2481de6bf8279",
		},
		{
			name: "ones",
			key:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			iv:   "ffffffffffffffffffffffffffffffff",
			want: "307609fb101012544bc175e317fb25ff330d0de25af6aad10505b89b1e09a8ecdd4672ccbb98c7f2c4e24af5272836c87cc73a8176b39ce9303b3e764e9be3e748f7651a7c7e813fd52490231e56f7c144e438e77711a6b0bafb60450c62d7d9b9241d1244fcb49da1e52b8013decdd48604fffc62676e703b3ab849cba6ea09",
		},
		{
			name: "pattern",
			key:  "505152535455565758595a5b5c5d5e5f0a1a2a3a4a5a6a7a8a9aaabacadaeafa",
			iv:   "0123456789abcdeffedcba9876543210",
			want: "aa81eafb8b8616ce3e5ce2222461c50a6ab4487756de4bd31c904f3d978afe56334f10dddf2b9531769a71050be4385fc2b6192c7a857be8b4fc28b709f08f11f20649e2eef24980f86c4c113641fed2f3f6fa2b91951206b801db15466517a6330adda6b35b265efd722e8677b48bfc15b44118de52d073b0ad0fe7594d6291",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := mustDecodeHex(t, test.key)
			iv := mustDecodeHex(t, test.iv)
			want := mustDecodeHex(t, test.want)
			if len(want) != 128 {
				t.Fatalf("fixture length = %d, want 128", len(want))
			}
			cipher, err := NewSnowVCipher(key, iv)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(want))
			cipher.XORKeyStream(got, got)
			if !bytes.Equal(got, want) {
				t.Fatalf("stream mismatch\n got %x\nwant %x", got, want)
			}
		})
	}
}

func TestSnowAESRoundFIPS197(t *testing.T) {
	input := mustDecodeHex(t, "00102030405060708090a0b0c0d0e0f0")
	want := mustDecodeHex(t, "5f72641557f5bc92f7be3b291db9f91a")
	var src, got, other [4]uint32
	for i := range 4 {
		src[i] = binary.LittleEndian.Uint32(input[4*i:])
	}
	aesRoundPairGeneric(&got, &other, &src, &src)
	var gotBytes [16]byte
	for i := range 4 {
		binary.LittleEndian.PutUint32(gotBytes[4*i:], got[i])
	}
	if !bytes.Equal(gotBytes[:], want) {
		t.Fatalf("AES round mismatch: got %x, want %x", gotBytes, want)
	}
	if got != other {
		t.Fatalf("paired equal inputs produced different outputs")
	}
}

func TestSnowVStreamChunkingAndInPlace(t *testing.T) {
	key := make([]byte, KeySize)
	iv := make([]byte, IVSize)
	plaintext := make([]byte, 255)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	oneShot, err := NewSnowVCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, len(plaintext))
	oneShot.XORKeyStream(want, plaintext)

	chunked, err := NewSnowVCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	got := append([]byte(nil), plaintext...)
	for i := range got {
		chunked.XORKeyStream(got[i:i+1], got[i:i+1])
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("byte-chunked stream mismatch")
	}

	withSuffix, err := NewSnowVCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	dst := bytes.Repeat([]byte{0xa5}, len(plaintext)+8)
	withSuffix.XORKeyStream(dst, plaintext)
	if !bytes.Equal(dst[:len(plaintext)], want) {
		t.Fatalf("out-of-place stream mismatch")
	}
	if !bytes.Equal(dst[len(plaintext):], bytes.Repeat([]byte{0xa5}, 8)) {
		t.Fatalf("destination suffix changed")
	}
}

func mustDecodeSpacedHex(t *testing.T, value string) []byte {
	t.Helper()
	return mustDecodeHex(t, strings.Join(strings.Fields(value), ""))
}

func TestSnowVPublishedInitializationTraces(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		iv    string
		trace string
	}{
		{
			name: "zero",
			key:  "0000000000000000000000000000000000000000000000000000000000000000",
			iv:   "00000000000000000000000000000000",
			trace: `
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
63 63 63 63 63 63 63 63 63 63 63 63 63 63 63 63
a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5 a5
ea ea ea ea eb eb eb eb eb eb eb eb eb eb eb eb
55 f7 f7 c2 e8 e8 dd 4a e8 dd 4a e8 dd 4a e8 e8
c7 2a 23 bf e8 93 73 30 23 bc 66 ec 94 d2 eb b2
a7 dd ca f3 13 87 61 02 6e ad f4 2b 54 e3 ef cf
6a 67 62 3e 6f 8a f9 79 1e cd 81 83 c5 86 8e 3a
45 10 1e 83 a2 c6 dd eb 40 86 38 2d ac fb 3b 65
3c c4 df 56 ec bf c1 06 6d ac 02 c5 0a 68 3c fe
0c cb e1 de 2e 41 af da 70 98 d5 60 19 20 06 98
53 cd 98 69 c7 78 ca de d7 db 45 9b 6f 45 8b 10
8d 94 0b e5 9f bd b1 61 c1 21 fc 29 7a 3d 0a 15
26 13 2c 14 9e af 12 cc d3 2f 35 76 f6 43 68 94
0e 75 be 09 54 18 1e f5 8a 60 a9 a9 54 3a 05 ff
dc 77 a4 97 23 eb 65 6a e1 8f 28 2c f1 de 1d 00`,
		},
		{
			name: "ones",
			key:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			iv:   "ffffffffffffffffffffffffffffffff",
			trace: `
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
d3 07 d2 07 d3 07 d2 07 d3 07 2d f8 2e f8 2d f8
65 f6 62 f6 65 f6 62 f6 65 f6 62 f6 65 f6 62 f6
fe 86 fe 86 f5 2d f2 2d 31 96 d7 54 6a e8 6a e8
8b d8 8a a5 c8 29 c6 26 7c 51 37 97 bf 9a c8 7c
21 c0 4a 14 e4 1c 34 95 d0 9c 96 e5 48 60 89 81
7c ce 64 29 1a cf 8f 4a 06 ca 55 65 3f c4 93 97
0a f9 1c 75 0f d3 80 e3 48 6b ff e5 c7 bb e3 d4
89 60 89 a2 e6 f0 7c 2c 92 ed 62 ed 9d 43 61 98
ff 04 bf 72 41 c0 7f 6b 17 fd 90 c8 8a 61 bf ca
97 88 78 33 20 08 2f f6 f9 34 45 18 6e 71 bc bc
7e 17 b4 ff 42 3a 2e 2c c7 c5 0f 84 5d 9b b3 ee
32 40 8c 85 58 e0 d2 7e f5 a3 a8 d7 63 32 25 dc
a2 93 73 c3 48 2b 3f 1a d3 3b b4 57 a3 0d 7f e4
72 e0 95 5b 9a 83 3a 3f db 98 68 56 35 80 b4 b0
94 9f be 85 a4 e5 35 7f bf 75 e9 86 4d 2c 7b a1`,
		},
		{
			name: "pattern",
			key:  "505152535455565758595a5b5c5d5e5f0a1a2a3a4a5a6a7a8a9aaabacadaeafa",
			iv:   "0123456789abcdeffedcba9876543210",
			trace: `
0a 1a 2a 3a 4a 5a 6a 7a 8a 9a aa ba ca da ea fa
66 d4 2d 92 ac 52 b6 44 63 3c c3 71 c3 91 c6 24
a2 d7 ea be 3f 04 8e 50 00 b1 7b 74 2f 34 5e 49
96 a7 34 ed fd 07 46 9d c8 f9 a2 91 fc 13 76 73
58 c8 70 73 d8 a2 a1 bd 03 e7 a1 4c c7 b7 db 89
7e 86 eb 71 d6 dc 00 99 d1 31 e3 1b 54 c5 3e f8
a8 ca ff 06 0d c0 9e 67 cc 95 62 16 17 19 8c f2
c0 99 3a 55 f3 e2 d7 8d 6a f7 e1 57 0f a1 63 02
39 8f a0 7e ab a2 73 89 94 f9 ac 3e 8e b1 ff 64
15 32 31 6a 42 5c 12 a6 39 ce 79 cb 30 43 47 1e
2e 7a 44 fd ad 23 77 5a f1 61 1c ca 5b b2 1e 95
93 69 c8 20 a9 37 d5 c8 b6 7a df 84 45 5e 13 c3
c1 0f 8d b5 fb 37 08 31 11 d1 c8 44 6e a2 ac 9e
13 ac 34 20 7b 01 b7 ab d3 57 02 a1 ed 98 9b dc
0b 15 43 a4 74 26 2c 76 a3 e2 73 57 28 4b dc 67
7b 79 91 96 cf 6b 76 27 f8 dd a1 89 bb af dc 93`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := mustDecodeHex(t, test.key)
			iv := mustDecodeHex(t, test.iv)
			trace := mustDecodeSpacedHex(t, test.trace)
			if len(trace) != 256 {
				t.Fatalf("trace length = %d, want 256", len(trace))
			}
			var state snowVState
			loadStateGeneric(&state, key, iv)
			for round := range 16 {
				var got [16]byte
				stepGeneric(&state, &got)
				want := trace[16*round : 16*(round+1)]
				if !bytes.Equal(got[:], want) {
					t.Fatalf("round %d: got %x, want %x", round+1, got, want)
				}
				for i := range 8 {
					state.hi[i] ^= binary.LittleEndian.Uint16(got[2*i:])
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
		})
	}
}
