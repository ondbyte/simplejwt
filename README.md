# simple JWT issue and validation using go-lang

this package provides a simple JWT issue and validation using go-lang

all you need to do is

```go
func main(){
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
```