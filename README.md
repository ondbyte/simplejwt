# simple JWT issue and validation using go-lang

this package provides a simple JWT issue and validation using go-lang

all you need to do is

```go
func main(){
    // use 16 bit len for aes 128, 32 for 192, 64 for 256
    // for example 16 bit for session token
    // 32 bit for access/refresh token
    key := []byte("12345678998765432112345678998765")
    cipher, err := simple_jwt.NewAESCipher(key)
    if err != nil {
    	panic(err)
    }
    jwtService := simple_jwt.NewService(cipher)
    type MyClaims struct {
    	Name string
    	Age  uint
    }
    claims := &MyClaims{
    	Name: "yadhu",
    	Age:  32,
    }
    token, err := jwtService.NewJWT(claims, time.Hour*24)
    if err != nil {
    	panic(err)
    }
    fmt.Println(token)
    newClaims := &MyClaims{}
    expired, err := jwtService.VerifyToken(token, newClaims)
    if v.expired != expired {
    	panic(fmt.Sprintf("expected expired=%v, but got expired=%v", v.expired, expired))
    }
    if err != nil {
    	panic(err)
    }
    fmt.Println(reflect.DeepEqual(newClaims, claims))
}
```