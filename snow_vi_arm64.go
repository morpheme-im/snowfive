//go:build arm64 && !purego && !noasm

package snowfive

import "unsafe"

func initializeViBackend(state *snowVState, key, iv []byte) {
	switch selectedBackend {
	case snowBackendARM64AES, snowBackendARM64SHA3:
		initStateViARM64(state, unsafe.SliceData(key), unsafe.SliceData(iv))
	default:
		initializeViGeneric(state, key, iv)
	}
}

func xorBlocksViBackend(state *snowVState, dst, src []byte) {
	switch selectedBackend {
	case snowBackendARM64SHA3:
		xorBlocksViARM64SHA3(state, unsafe.SliceData(dst), unsafe.SliceData(src), uintptr(len(src)/16))
	case snowBackendARM64AES:
		xorBlocksViARM64(state, unsafe.SliceData(dst), unsafe.SliceData(src), uintptr(len(src)/16))
	default:
		xorBlocksViGeneric(state, dst, src)
	}
}

//go:noescape
func initStateViARM64(state *snowVState, key, iv *byte)

//go:noescape
func xorBlocksViARM64(state *snowVState, dst, src *byte, blocks uintptr)

//go:noescape
func xorBlocksViARM64SHA3(state *snowVState, dst, src *byte, blocks uintptr)
