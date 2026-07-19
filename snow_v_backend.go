package snowfive

type snowBackend uint8

const (
	snowBackendGeneric snowBackend = iota
	snowBackendAMD64AES
	snowBackendAMD64XMM
	snowBackendAMD64VAES
	snowBackendARM64AES
	snowBackendARM64SHA3
)

func selectAMD64Backend(aes, ssse3, avx2, vaes bool) snowBackend {
	switch {
	case aes && avx2 && vaes:
		return snowBackendAMD64VAES
	case aes && ssse3:
		return snowBackendAMD64XMM
	case aes:
		return snowBackendAMD64AES
	default:
		return snowBackendGeneric
	}
}

func selectARM64Backend(asimd, aes, sha3 bool) snowBackend {
	switch {
	case asimd && aes && sha3:
		return snowBackendARM64SHA3
	case asimd && aes:
		return snowBackendARM64AES
	default:
		return snowBackendGeneric
	}
}
