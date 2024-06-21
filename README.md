# simple JWT issue and validation using go-lang

this package provides a simple JWT issue and validation using go-lang

all you need to do is

```go
func main(){
    secret := "123" // change this accordingly
    type MyClaims struct {
    	Name string
    	Age  uint
        Iat int64
    }
    jwtService := simplejwt.NewService[MyClaims](simplejwt.NewHMACSHA256Signer(secret))
    claims := &MyClaims{
    	Name: "yadhu",
    	Age:  32,
        Iat: time.Now().Unix()
    }
    token, err := jwtService.NewJWT(claims)
    if err != nil {
    	panic(err)
    }
    fmt.Println(token)
    verifiedClaims,err = jwtService.VerifyJWT(token)
    if err == nil {
    	panic(err)
    }
    maxJwtValidity:=Duration.Second*1000
    if verifiedClaims.Iat<time.Now().Add(-1*maxJwtValidity){
        // validity is expired
    }
}
```