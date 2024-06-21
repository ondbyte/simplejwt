package simplejwt

import (
	"encoding/json"
	"errors"
	"strings"
)

type Service[claims any] struct {
	signer Signer
}

func NewService[claims any](secret Signer) *Service[claims] {
	return &Service[claims]{signer: secret}
}

// generates a new JWT token
// claims should be a struct ptr
func (s *Service[c]) NewJWT(claims *c) (string, error) {
	claimsJSON, err := json.MarshalIndent(claims, "", "")
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

// verifies the signature of the jwt
// you need to verify whether its expired or not using claims
func (j *Service[c]) VerifyJWT(token string) (claims *c, err error) {
	splitted := strings.Split(token, ".")
	if len(splitted) != 3 {
		return nil, errors.New("token must have three component separated by '.'")
	}
	sign, err := base64UrlDecode(splitted[2])
	if err != nil {
		return nil, err
	}
	valid, err := j.signer.Verify(splitted[0]+"."+splitted[1], sign)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, errors.New("invalid signature")
	}
	bClaimsJson, err := base64UrlDecode(splitted[1])
	if err != nil {
		return nil, err
	}
	claims = new(c)
	err = json.Unmarshal([]byte(bClaimsJson), claims)
	if err != nil {
		return nil, err
	}
	return claims, nil
}
