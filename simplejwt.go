package simplejwt

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

type Cipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
}

// aes cypher ecrytpts and decrypts data thats it.
type aesCipher struct {
	block cipher.Block
}

func (a *aesCipher) Encrypt(plaintext []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(a.block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (a *aesCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(a.block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

type Service struct {
	HMACSHA256Signer
}

func NewService(secret string) *Service {
	return &Service{*NewHMACSHA256Signer(secret)}
}

type baseClaims struct {
	Claims interface{} `json:"claims"`
	Expiry time.Time   `json:"expiry"`
}

func newClaims(data any, expiryDuration time.Duration) *baseClaims {
	return &baseClaims{
		Claims: data,
		Expiry: time.Now().Add(expiryDuration),
	}
}

func newEmptyClaims(data any) *baseClaims {
	return &baseClaims{
		Claims: data,
	}
}

// generates a new JWT token
// claims should be a struct ptr
func (j *Service) NewJWT(claims any, validDuration time.Duration) (string, error) {
	bclaims := newClaims(claims, validDuration)
	bclaims.Expiry = time.Now().Add(validDuration)
	claimsJSON, err := json.MarshalIndent(bclaims, "", "")
	if err != nil {
		return "", err
	}
	header,payload, sign, err := j.Sign(string(claimsJSON))
	if err != nil {
		return "", err
	}
	return header + "." + payload + "." + sign, nil
}

// verifies the token and scans the claims into the claims parameter
func (j *Service) VerifyJWT(token string, claims any) (err error) {
	splitted := strings.Split(token, ".")
	if len(splitted) != 3 {
		return errors.New("token must have three component separated by '.'")
	}
	claims64 := splitted[1]
	sign := splitted[2]
	_, actualSign, err := j.Sign(claims64)
	if err != nil {
		return err
	}
	if sign != actualSign {
		return errors.New("invalid signature")
	}
	bClaimsJson, err := base64.StdEncoding.DecodeString(claims64)
	if err != nil {
		return err
	}
	bClaims := newEmptyClaims(claims)
	err = json.Unmarshal(bClaimsJson, bClaims)
	if err != nil {
		return err
	}
	if time.Now().Unix() > bClaims.Expiry.Unix() {
		return errors.New("token has expired")
	}
	return nil
}
