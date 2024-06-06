package simplejwt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"
)

type Cipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// aes cypher ecrytpts and decrypts data thats it.
type aesCipher struct {
	block cipher.Block
}

// creates a new aes based cipher, expects a 16, 24 or 32 byte key
func NewAESCipher(key []byte) (Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &aesCipher{block: block}, nil
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
	cipher Cipher
}

func NewService(cipher Cipher) *Service {
	return &Service{cipher: cipher}
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
func (j *Service) NewJWT(claims any, validDuration time.Duration) (string, error) {
	bclaims := newClaims(claims, validDuration)
	claimsJSON, err := json.Marshal(bclaims)
	if err != nil {
		return "", err
	}

	encryptedClaims, err := j.cipher.Encrypt(claimsJSON)
	if err != nil {
		return "", err
	}

	token := base64.StdEncoding.EncodeToString(encryptedClaims)
	return token, nil
}

// verifies the token and scans the claims into the claims parameter
func (j *Service) VerifyToken(token string, claims any) (expired bool, err error) {
	encryptedClaims, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return false, err
	}

	decryptedClaims, err := j.cipher.Decrypt(encryptedClaims)
	if err != nil {
		return false, err
	}

	bclaims := newEmptyClaims(claims)
	if err := json.Unmarshal(decryptedClaims, bclaims); err != nil {
		return false, err
	}

	return time.Now().Unix() > bclaims.Expiry.Unix(), nil
}
