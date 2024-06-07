package simplejwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// Struct to hold the HMAC Hash object
type _HMACSHA256Signer struct {
	secret []byte
	h      hash.Hash
}

// Header implements Signer.
func (signer *_HMACSHA256Signer) Header() string {
	return `{"alg":"HS256","typ":"JWT"}`
}

// Constructor for HMACSHA256Signer
func NewHMACSHA256Signer(secret string) Signer {
	return &_HMACSHA256Signer{
		secret: []byte(secret),
		h:      hmac.New(sha256.New, []byte(secret)),
	}
}

func (signer *_HMACSHA256Signer) Sign(data string) (sign string, err error) {
	// Reset the HMAC Hash object
	signer.h.Reset()

	// Write the message to it
	_, err = signer.h.Write([]byte(data))
	if err != nil {
		return "", err
	}

	// Get the final HMAC as a byte array
	signature := signer.h.Sum(nil)

	return string(signature), nil
}
