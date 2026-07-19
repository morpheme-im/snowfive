package snowfive

import (
	"strconv"
	"testing"
)

var benchmarkSnowViCipherSink *SnowViCipher

func BenchmarkNewSnowViCipher(b *testing.B) {
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
		stream, err := NewSnowViCipher(key[:], iv[:])
		if err != nil {
			b.Fatal(err)
		}
		benchmarkSnowViCipherSink = stream
	}
}

func BenchmarkSnowViXORKeyStream(b *testing.B) {
	for _, size := range benchmarkSizes {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			var key [KeySize]byte
			var iv [IVSize]byte
			buffer := make([]byte, size)
			for i := range buffer {
				buffer[i] = byte(i*17 + 3)
			}
			stream, err := NewSnowViCipher(key[:], iv[:])
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				stream.XORKeyStream(buffer, buffer)
			}
		})
	}
}

func BenchmarkSnowViCipherWithSetup(b *testing.B) {
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
				stream, err := NewSnowViCipher(key[:], iv[:])
				if err != nil {
					b.Fatal(err)
				}
				stream.XORKeyStream(buffer, buffer)
			}
		})
	}
}
