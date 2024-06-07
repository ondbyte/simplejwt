package simplejwt_test

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/ondbyte/simplejwt"
)

func TestSimpleJwt(t *testing.T) {
	tests := []struct {
		name          string
		tokenDuration time.Duration
		expectedErr   bool
	}{
		{
			name:          "hour",
			tokenDuration: time.Hour,
			expectedErr:   false,
		},
		{
			name:          "minute",
			tokenDuration: time.Minute,
			expectedErr:   false,
		},
		{
			name:          "second",
			tokenDuration: time.Second,
			expectedErr:   false,
		},
		{
			name:          "invalid",
			tokenDuration: time.Minute * -1,
			expectedErr:   true,
		},
	}
	for _, v := range tests {
		tokenDuration := v.tokenDuration
		secret := "123" // change this accordingly
		jwtService := simplejwt.NewService(simplejwt.NewHMACSHA256Signer(secret))
		type MyClaims struct {
			Name string
			Age  uint
		}
		claims := &MyClaims{
			Name: "yadhu",
			Age:  32,
		}
		token, err := jwtService.NewJWT(claims, tokenDuration)
		if err != nil {
			panic(err)
		}
		fmt.Println(token)
		newClaims := &MyClaims{}
		err = jwtService.VerifyJWT(token, newClaims)
		if v.expectedErr && err == nil {
			panic("expected error but got nil")
		}
		if !v.expectedErr && err != nil {
			panic("expected no err but got err")
		}
		fmt.Println(reflect.DeepEqual(newClaims, claims))
	}
}
