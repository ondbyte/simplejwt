package simplejwt_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ondbyte/simplejwt"
)

func TestSimpleJwt(t *testing.T) {
	tests := []struct {
		name           string
		tokenDuration  time.Duration
		expired        bool
		messWithClaims bool
	}{
		{
			name:          "hour",
			tokenDuration: time.Hour,
			expired:       false,
		},
		{
			name:          "minute",
			tokenDuration: time.Minute,
			expired:       false,
		},
		{
			name:          "second",
			tokenDuration: time.Second,
			expired:       false,
		},
		{
			name:          "invalid",
			tokenDuration: time.Minute * -1,
			expired:       true,
		},
		{
			name:           "invalid",
			tokenDuration:  time.Minute * -1,
			expired:        false,
			messWithClaims: true,
		},
	}
	for _, v := range tests {
		secret := "123" // change this accordingly

		type MyClaims struct {
			Name string
			Age  uint
			Iat  int64
		}

		jwtService := simplejwt.NewService[MyClaims](simplejwt.NewHMACSHA256Signer(secret))
		claims := &MyClaims{
			Name: "yadhu",
			Age:  32,
			Iat:  time.Now().Add(v.tokenDuration).Unix(),
		}
		token, err := jwtService.NewJWT(claims)
		if err != nil {
			panic(err)
		}
		fmt.Println(token)
		if v.messWithClaims {
			splitted := strings.Split(token, ".")
			splitted[1] += "yadhu"
			token = strings.Join(splitted, ".")
		}
		verifiedClaims, err := jwtService.VerifyJWT(token)
		if v.messWithClaims && err == nil {
			panic("expected error while VerifyJWT")
		}
		if !v.messWithClaims && err != nil {
			panic("expected no error while VerifyJWT")
		}
		if v.messWithClaims {
			continue
		}
		if verifiedClaims.Iat <= time.Now().Unix() {
			if !v.expired {
				panic("token cannot be expired")
			}
		}
		fmt.Println(reflect.DeepEqual(verifiedClaims, claims))
	}
}
