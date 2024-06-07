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
    if err == nil {
    	panic(err)
    }
    if !v.expectedErr && err != nil {
    	panic(err)
    }
    fmt.Println(reflect.DeepEqual(newClaims, claims))
}
```