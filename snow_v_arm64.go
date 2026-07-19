//go:build arm64 && !purego && !noasm

package snowfive

import (
	"unsafe"

	"golang.org/x/sys/cpu"
)

var (
	hasARM64AES     = cpu.ARM64.HasASIMD && cpu.ARM64.HasAES
	hasARM64SHA3    = hasARM64AES && cpu.ARM64.HasSHA3
	selectedBackend = selectARM64Backend(
		cpu.ARM64.HasASIMD,
		cpu.ARM64.HasAES,
		cpu.ARM64.HasSHA3,
	)
)

func initializeBackend(state *snowVState, key, iv []byte) {
	switch selectedBackend {
	case snowBackendARM64AES, snowBackendARM64SHA3:
		initStateARM64(state, unsafe.SliceData(key), unsafe.SliceData(iv))
	default:
		initializeGeneric(state, key, iv)
	}
}

func xorBlocksBackend(state *snowVState, dst, src []byte) {
	switch selectedBackend {
	case snowBackendARM64SHA3:
		xorBlocksARM64SHA3(state, unsafe.SliceData(dst), unsafe.SliceData(src), uintptr(len(src)/16))
	case snowBackendARM64AES:
		xorBlocksARM64(state, unsafe.SliceData(dst), unsafe.SliceData(src), uintptr(len(src)/16))
	default:
		xorBlocksGeneric(state, dst, src)
	}
}

//go:noescape
func initStateARM64(state *snowVState, key, iv *byte)

//go:noescape
func xorBlocksARM64(state *snowVState, dst, src *byte, blocks uintptr)

//go:noescape
func xorBlocksARM64SHA3(state *snowVState, dst, src *byte, blocks uintptr)
