package simplejwt

import (
	"crypto/ecdsa"
)

type Signer interface {
	// Method to create a HMAC SHA256 signature
	// returned signature will be raw/un encoded
	Sign(data string) (sign string, err error)

	// returns the header string
	Header() string
}

type EcdsaSigner struct {
	key *ecdsa.PrivateKey
}

// Header implements Signer.
func (e *EcdsaSigner) Header() string {
	return ""
}

// Sign implements Signer.
func (e *EcdsaSigner) Sign(data string) (sign string, err error) {
	dsa.s
}

func NewEcdsaSigner() Signer {
	return &EcdsaSigner{}
}
