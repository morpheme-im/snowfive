package snowfive

import (
	"fmt"
	"io"
)

const (
	redactedState       = "<snowfive.snowVState redacted>"
	redactedCipherState = "<snowfive.snowCipherState redacted>"
)

var (
	_ fmt.Formatter  = snowVState{}
	_ fmt.Stringer   = snowVState{}
	_ fmt.GoStringer = snowVState{}
	_ fmt.Formatter  = (*SnowVCipher)(nil)
	_ fmt.Stringer   = (*SnowVCipher)(nil)
	_ fmt.GoStringer = (*SnowVCipher)(nil)
	_ fmt.Formatter  = (*SnowViCipher)(nil)
	_ fmt.Stringer   = (*SnowViCipher)(nil)
	_ fmt.GoStringer = (*SnowViCipher)(nil)
)

// Format redacts every verb for which fmt invokes Formatter. The fmt package
// reserves %T and %p: %T reveals only the type, while %p on a pointer reveals
// only its address. The invalid combination of a struct value with %p bypasses
// Formatter while fmt reports the error and can expose the struct's fields.
func (snowVState) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redactedState)
}

func (snowVState) String() string {
	return redactedState
}

func (snowVState) GoString() string {
	return redactedState
}

// These methods promote through the existing anonymous snowCipherState field,
// redacting both values and pointers without changing either public struct.
func (snowCipherState) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redactedCipherState)
}

func (snowCipherState) String() string {
	return redactedCipherState
}

func (snowCipherState) GoString() string {
	return redactedCipherState
}
