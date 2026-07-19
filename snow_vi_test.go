package snowfive

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

type snowViPublishedCase struct {
	name      string
	key       string
	iv        string
	initTrace string
	keystream string
}

var snowViPublishedCases = [...]snowViPublishedCase{
	{
		name: "all-zero",
		key:  "0000000000000000000000000000000000000000000000000000000000000000",
		iv:   "00000000000000000000000000000000",
		initTrace: "0000000000000000000000000000000063636363636363636363636363636363" +
			"a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a54f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f" +
			"7a5b5a5a795b5a5a5a5a5a5a5b5a5a5a4d51be6e190a0aa9a4fefeaef4d6d6d6" +
			"7a97fb47d25762468acadf1ed1484d3c8c97873e900038d52df346c32ff7970c108" +
			"937a10246610a6707b54e941e0e3b9436b9e33b0f109adc89b3d5a3aef82dbaea" +
			"9fd068b9a11e436267f87f4a05ac0c1512c2388009465a55eff889816c9775829e" +
			"c8a8737038cd5ec57e219d9816ed45923c437ad7b0e52261728547dcbee938ac0b7" +
			"05cb9852a4249ba0e8737c365282cefab7ca957aef8d94e2938c8cd",
		keystream: "501719e175e49fb741babf6ba5de60fecda8b34d7ec4c6429755c19d2f671871" +
			"8957d326cb46502ceb814ccd6ea53aaedd6c92fbf3921e8bd7317be2201531bb" +
			"093ee872e9eb4034e9b71a4ac2b54bd9f00f5adc06d2e6b59fb75a01bef61314" +
			"1c8ab202ee38e2850cca606ab875cd124103b32fa5145ddf54e7a07b0f3eb77a",
	},
	{
		name: "all-ff",
		key:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		iv:   "ffffffffffffffffffffffffffffffff",
		initTrace: "ffffffffffffffffffffffffffffffff9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c" +
			"cf09cc09d610d710cc36cd36d610d710e53172b0e89153dd75b03e3154ddd2912" +
			"2b331dae505d791667b7dfb3f84a3ffcdd6c9029e24763a1982bc3c79d19d62e" +
			"1a3fbacea2b6d68a1a751043a460bdbb2305268824b8809ac92d57d007ead0c79" +
			"747ceb019502a71a2ff5077c8996ada106ebd4c1d85f126181e1a9551b3bdfaa" +
			"5dff5a66a36716f7dcc2ec3fda643dad4dee832729150a3ef33c9ed579d97950a" +
			"4a0dd21a01c406831e62e9d38ef0dd33cc5721b4dfa2f2ccdc91fb173fbf3e8d" +
			"0e3f114e32a20ff56df097cabf8041e24ae32569f7b0882304d8037cb23b2",
		keystream: "187153c0881d00e8bfa0e2fafe715ea38de7fd87a676171ca15e475b4da7b87d" +
			"ad86fcfd9e0fbbbeef6af45f3929c1239bf3e5efb7d690e69d607dc5c04ff477" +
			"4c9f06a2b6363e52fcb30b8fd39fe76e1164a6bda4734a76ee5fe9ff28ffc139" +
			"f9c6f17d48430c18df3cf45d235edcb3f6d4d10bf675f4acc4fbb088cc5ec490",
	},
	{
		name: "patterned",
		key:  "505152535455565758595a5b5c5d5e5f0a1a2a3a4a5a6a7a8a9aaabacadaeafa",
		iv:   "0123456789abcdeffedcba9876543210",
		initTrace: "0a1a2a3a4a5a6a7a8a9aaabacadaeafa38eea4da77246290a5ff09e36c855029" +
			"c36278ce974329977eb0df7c2e5b9ba2eabacd104a5f1ddd7158961611e9596e" +
			"98e8c1c430189df297f00dce37a169bcd982ee9cdb0304cc23225ed18bdcaeab" +
			"3000671244dd555212f4ae68a0daa3d08748b7acf4670037ce67a742714ee1189" +
			"1279bf8ca8ea12d826b6cf7b7efa9ceb4f016c99dd97a3e763071f0992401a72" +
			"4aab30ed4fccfe8418ac5748f53c447147bfa54f52fad01ab96d6ccda01ee8623" +
			"fdd54f2b8dd60d6cd0b3deda7042e10c73a00fe287781f5c1b920c0016b80cb1" +
			"49b29cdfda0c95b9d318969181a2eceabad38490c8cfb6a1f580e06fd77433",
		keystream: "3a40f540f547f00f2d6fe3d001c1403ac7059a3919784fab414bbef75925e523" +
			"7e12454aea9e011ce44629adf3f7a8bb7e26bd6c4295ce626a70b64b4148f7b" +
			"3b4e233575af9ba7a7634a6bb22c740773ebeebed5a9494d53a2b9586030d687" +
			"d28f97ec983fd76413ed6551bdf89f1eb30c24d1c612d5a9314d764d8227e4dbf",
	},
}

func TestSnowViPublishedVectors(t *testing.T) {
	for _, test := range snowViPublishedCases {
		t.Run(test.name, func(t *testing.T) {
			key := decodeSnowViHex(t, test.key, KeySize)
			iv := decodeSnowViHex(t, test.iv, IVSize)
			want := decodeSnowViHex(t, test.keystream, 128)
			stream, err := NewSnowViCipher(key, iv)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(want))
			stream.XORKeyStream(got, got)
			if !bytes.Equal(got, want) {
				t.Fatalf("keystream = %x, want %x", got, want)
			}
		})
	}
}

func TestSnowViInitializationTraces(t *testing.T) {
	for _, test := range snowViPublishedCases {
		t.Run(test.name, func(t *testing.T) {
			key := decodeSnowViHex(t, test.key, KeySize)
			iv := decodeSnowViHex(t, test.iv, IVSize)
			want := decodeSnowViHex(t, test.initTrace, 256)
			var state snowVState
			loadStateGeneric(&state, key, iv)
			got := make([]byte, 0, len(want))
			for round := range 16 {
				var discarded [16]byte
				stepViGeneric(&state, &discarded)
				got = append(got, discarded[:]...)
				for i := range 8 {
					state.hi[i] ^= binary.LittleEndian.Uint16(discarded[2*i:])
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
			if !bytes.Equal(got, want) {
				t.Fatalf("initialization trace = %x, want %x", got, want)
			}
			var initialized snowVState
			initializeViGeneric(&initialized, key, iv)
			if state != initialized {
				t.Fatal("trace initialization state differs from initializeViGeneric")
			}
		})
	}
}

func decodeSnowViHex(t *testing.T, value string, size int) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != size {
		t.Fatalf("decoded length = %d, want %d", len(decoded), size)
	}
	return decoded
}
