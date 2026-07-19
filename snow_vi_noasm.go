//go:build purego || noasm || (!amd64 && !arm64)

package snowfive

func initializeViBackend(state *snowVState, key, iv []byte) {
	initializeViGeneric(state, key, iv)
}

func xorBlocksViBackend(state *snowVState, dst, src []byte) {
	xorBlocksViGeneric(state, dst, src)
}
