package snowfive

import (
	"fmt"
)

const (
	redactedState       = "<snowfive.snowVState redacted>"
	redactedCipherState = "<snowfive.snowCipherState redacted>"
)

var (
	_ fmt.Stringer = snowVState{}
	_ fmt.Stringer = (*SnowVCipher)(nil)
	_ fmt.Stringer = (*SnowViCipher)(nil)
)

func (snowVState) String() string {
	return redactedState
}

func (snowCipherState) String() string {
	return redactedCipherState
}
