// Package snowfive implements the SNOW-V and SNOW-Vi synchronous stream
// ciphers.
//
// Both variants provide confidentiality only. They do not authenticate
// ciphertext; applications that need integrity must use a separate, secure
// authentication construction. SNOW-V and SNOW-Vi keystreams are not
// interchangeable.
package snowfive
