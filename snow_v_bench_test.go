package snowfive

import (
	"crypto/aes"
	"crypto/cipher"
	"strconv"
	"testing"

	"golang.org/x/crypto/chacha20"
)

var benchmarkCipherSink *SnowVCipher

var benchmarkSizes = [...]int{64, 256, 1024, 2048, 4096, 8192, 16384}

func BenchmarkNewCipher(b *testing.B) {
	var key [KeySize]byte
	var iv [IVSize]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range iv {
		iv[i] = byte(3*i + 1)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		cipher, err := NewSnowVCipher(key[:], iv[:])
		if err != nil {
			b.Fatal(err)
		}
		benchmarkCipherSink = cipher
	}
}

func BenchmarkXORKeyStream(b *testing.B) {
	for _, size := range benchmarkSizes {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			var key [KeySize]byte
			var iv [IVSize]byte
			buffer := make([]byte, size)
			for i := range buffer {
				buffer[i] = byte(i*17 + 3)
			}
			cipher, err := NewSnowVCipher(key[:], iv[:])
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				cipher.XORKeyStream(buffer, buffer)
			}
		})
	}
}

func BenchmarkCipherWithSetup(b *testing.B) {
	for _, size := range benchmarkSizes {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			var key [KeySize]byte
			var iv [IVSize]byte
			buffer := make([]byte, size)
			for i := range buffer {
				buffer[i] = byte(i*17 + 3)
			}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				cipher, err := NewSnowVCipher(key[:], iv[:])
				if err != nil {
					b.Fatal(err)
				}
				cipher.XORKeyStream(buffer, buffer)
			}
		})
	}
}

// BenchmarkCipherComparison measures steady-state in-place throughput with
// algorithm-native nonce sizes and the same 256-bit key and payload.
func BenchmarkCipherComparison(b *testing.B) {
	var key [KeySize]byte
	var iv [IVSize]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range iv {
		iv[i] = byte(3*i + 1)
	}

	algorithms := [...]struct {
		name    string
		new     func(*testing.B) cipher.Stream
		backend func() int
	}{
		{
			name: "SNOW-Vi",
			new: func(b *testing.B) cipher.Stream {
				stream, err := NewSnowViCipher(key[:], iv[:])
				if err != nil {
					b.Fatal(err)
				}
				return stream
			},
			backend: func() int { return int(selectedBackend) },
		},
		{
			name: "SNOW-V",
			new: func(b *testing.B) cipher.Stream {
				stream, err := NewSnowVCipher(key[:], iv[:])
				if err != nil {
					b.Fatal(err)
				}
				return stream
			},
			backend: func() int { return int(selectedBackend) },
		},
		{
			name: "AES-256-CTR",
			new: func(b *testing.B) cipher.Stream {
				block, err := aes.NewCipher(key[:])
				if err != nil {
					b.Fatal(err)
				}
				return cipher.NewCTR(block, iv[:])
			},
			backend: func() int { return -1 },
		},
		{
			name: "ChaCha20",
			new: func(b *testing.B) cipher.Stream {
				stream, err := chacha20.NewUnauthenticatedCipher(key[:], iv[:chacha20.NonceSize])
				if err != nil {
					b.Fatal(err)
				}
				return stream
			},
			backend: func() int { return -1 },
		},
	}

	for _, algorithm := range algorithms {
		b.Run(algorithm.name, func(b *testing.B) {
			for _, size := range benchmarkSizes {
				b.Run(strconv.Itoa(size), func(b *testing.B) {
					buffer := make([]byte, size)
					for i := range buffer {
						buffer[i] = byte(i*17 + 3)
					}
					stream := algorithm.new(b)
					b.SetBytes(int64(size))
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						stream.XORKeyStream(buffer, buffer)
					}
					b.StopTimer()
					b.ReportMetric(float64(algorithm.backend()), "cipher-backend")
				})
			}
		})
	}
}
