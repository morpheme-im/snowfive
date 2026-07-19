package snowfive

import (
	"bytes"
	"strings"
	"testing"
)

func TestSnowSelectAMD64BackendTruthTable(t *testing.T) {
	want := [...]snowBackend{
		snowBackendGeneric,
		snowBackendAMD64AES,
		snowBackendGeneric,
		snowBackendAMD64XMM,
		snowBackendGeneric,
		snowBackendAMD64AES,
		snowBackendGeneric,
		snowBackendAMD64XMM,
		snowBackendGeneric,
		snowBackendAMD64AES,
		snowBackendGeneric,
		snowBackendAMD64XMM,
		snowBackendGeneric,
		snowBackendAMD64VAES,
		snowBackendGeneric,
		snowBackendAMD64VAES,
	}
	for mask, expected := range want {
		aes := mask&1 != 0
		ssse3 := mask&2 != 0
		avx2 := mask&4 != 0
		vaes := mask&8 != 0
		if got := selectAMD64Backend(aes, ssse3, avx2, vaes); got != expected {
			t.Fatalf("mask %04b (%t,%t,%t,%t): backend = %d, want %d", mask, aes, ssse3, avx2, vaes, got, expected)
		}
	}
}

func TestSnowSelectARM64BackendTruthTable(t *testing.T) {
	want := [...]snowBackend{
		snowBackendGeneric,
		snowBackendGeneric,
		snowBackendGeneric,
		snowBackendARM64AES,
		snowBackendGeneric,
		snowBackendGeneric,
		snowBackendGeneric,
		snowBackendARM64SHA3,
	}
	for mask, expected := range want {
		asimd := mask&1 != 0
		aes := mask&2 != 0
		sha3 := mask&4 != 0
		if got := selectARM64Backend(asimd, aes, sha3); got != expected {
			t.Fatalf("mask %03b (%t,%t,%t): backend = %d, want %d", mask, asimd, aes, sha3, got, expected)
		}
	}
}

func validateExpectedDisabled(t *testing.T, profile, disabled string, features []string) map[string]bool {
	t.Helper()
	if len(profile) != len(features) {
		t.Fatalf("SNOWFIVE_EXPECT_PROFILE = %q, want %d bits", profile, len(features))
	}
	expected := make(map[string]bool, len(features))
	for index, feature := range features {
		switch profile[index] {
		case '0':
			expected[feature] = true
		case '1':
		default:
			t.Fatalf("SNOWFIVE_EXPECT_PROFILE = %q, bit %d is not 0 or 1", profile, index)
		}
	}
	actual := make(map[string]bool, len(features))
	if disabled != "" {
		for _, feature := range strings.Split(disabled, ",") {
			if actual[feature] {
				t.Fatalf("SNOWFIVE_EXPECT_DISABLED repeats %q", feature)
			}
			if !expected[feature] {
				t.Fatalf("SNOWFIVE_EXPECT_DISABLED names unexpected feature %q for profile %q", feature, profile)
			}
			actual[feature] = true
		}
	}
	for feature := range expected {
		if !actual[feature] {
			t.Fatalf("SNOWFIVE_EXPECT_DISABLED omits %q for profile %q", feature, profile)
		}
	}
	return actual
}

func exerciseSelectedBackendPublishedBlocks(t *testing.T) {
	t.Helper()
	key := make([]byte, KeySize)
	iv := make([]byte, IVSize)
	tests := []struct {
		name string
		new  func([]byte, []byte) (interface{ XORKeyStream([]byte, []byte) }, error)
		want string
	}{
		{
			name: "SNOW-V",
			new: func(key, iv []byte) (interface{ XORKeyStream([]byte, []byte) }, error) {
				return NewSnowVCipher(key, iv)
			},
			want: "69ca6daf9ae3b72db134a85a837e419d",
		},
		{
			name: "SNOW-Vi",
			new: func(key, iv []byte) (interface{ XORKeyStream([]byte, []byte) }, error) {
				return NewSnowViCipher(key, iv)
			},
			want: "501719e175e49fb741babf6ba5de60fe",
		},
	}
	for _, test := range tests {
		stream, err := test.new(key, iv)
		if err != nil {
			t.Fatalf("%s constructor: %v", test.name, err)
		}
		var got [16]byte
		stream.XORKeyStream(got[:], got[:])
		if want := mustDecodeHex(t, test.want); !bytes.Equal(got[:], want) {
			t.Fatalf("%s published block = %x, want %x", test.name, got, want)
		}
	}
}
