//go:build purego || noasm || (!amd64 && !arm64)

package snowfive

const selectedBackend = snowBackendGeneric

func initializeBackend(state *snowVState, key, iv []byte) {
	initializeGeneric(state, key, iv)
}

func xorBlocksBackend(state *snowVState, dst, src []byte) {
	xorBlocksGeneric(state, dst, src)
}
