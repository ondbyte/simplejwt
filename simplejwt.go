package simplejwt

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type Service struct {
	signer Signer
}

func NewService(secret Signer) *Service {
	return &Service{signer: secret}
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
func (s *Service) NewJWT(claims any, validDuration time.Duration) (string, error) {
	bclaims := newClaims(claims, validDuration)
	bclaims.Expiry = time.Now().Add(validDuration)
	claimsJSON, err := json.MarshalIndent(bclaims, "", "")
	if err != nil {
		return "", err
	}
	header := base64UrlEncode(s.signer.Header())
	payload := base64UrlEncode(string(claimsJSON))
	sign, err := s.signer.Sign(header + "." + payload)
	if err != nil {
		return "", err
	}
	return header + "." + payload + "." + base64UrlEncode(sign), nil
}

// verifies the token and scans the claims into the claims parameter
func (j *Service) VerifyJWT(token string, claims any) (err error) {
	splitted := strings.Split(token, ".")
	if len(splitted) != 3 {
		return errors.New("token must have three component separated by '.'")
	}
	sign, err := base64UrlDecode(splitted[2])
	if err != nil {
		return err
	}
	valid, err := j.signer.Verify(splitted[0]+"."+splitted[1], sign)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid signature")
	}
	bClaimsJson, err := base64UrlDecode(splitted[1])
	if err != nil {
		return err
	}
	bClaims := newEmptyClaims(claims)
	err = json.Unmarshal([]byte(bClaimsJson), bClaims)
	if err != nil {
		return err
	}
	if time.Now().Unix() > bClaims.Expiry.Unix() {
		return errors.New("token has expired")
	}
	return nil
}
