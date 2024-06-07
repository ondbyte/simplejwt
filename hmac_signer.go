package simplejwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
)

// Struct to hold the HMAC Hash object
type HMACSHA256Signer struct {
	secret []byte
	h      hash.Hash
}

// Constructor for HMACSHA256Signer
func NewHMACSHA256Signer(secret string) *HMACSHA256Signer {
	return &HMACSHA256Signer{
		secret: []byte(secret),
		h:      hmac.New(sha256.New, []byte(secret)),
	}
}

// Method to create a HMAC SHA256 signature
func (signer *HMACSHA256Signer) Sign(jsonPayload string) (headerEndoded,payload, sign string, err error) {
	header := base64UrlEncode(`{"alg":"HS256","typ":"JWT"}`)
	// Encode header and payload to Base64Url
	headerEncoded := base64UrlEncode(header)
	payloadEncoded := base64UrlEncode(jsonPayload)

	// Create the message
	message := fmt.Sprintf("%s.%s", headerEncoded, payloadEncoded)

	// Reset the HMAC Hash object
	signer.h.Reset()

	// Write the message to it
	_, err = signer.h.Write([]byte(message))
	if err != nil {
		return "", "","", err
	}

	// Get the final HMAC as a byte array
	signature := signer.h.Sum(nil)

	// Encode the HMAC to Base64Url
	signatureEncoded := base64UrlEncodeBytes(signature)

	return headerEndoded,payloadEncoded, signatureEncoded, nil
}

// Function to encode a string to Base64Url
func base64UrlEncode(input string) string {
	return base64UrlEncodeBytes([]byte(input))
}

// Function to encode bytes to Base64Url
func base64UrlEncodeBytes(input []byte) string {
	encoded := base64.URLEncoding.EncodeToString(input)
	return encoded
}
