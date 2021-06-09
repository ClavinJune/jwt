# jwt [![Go Reference](https://pkg.go.dev/badge/github.com/ClavinJune/jwt.svg)](https://pkg.go.dev/github.com/ClavinJune/jwt)
JWT Helper

## Usage

```shell
go get -u github.com/ClavinJune/jwt@latest
```

## Example

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/ClavinJune/jwt"
)

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	j := jwt.JWT{
		Header: jwt.Header{
			Alg: jwt.HeaderAlgRS256,
			Typ: jwt.HeaderTypJWT,
		},
		Claims: jwt.Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Iss: "issuer",
				Sub: "subject",
				Aud: []string{"aud1", "aud2"},
				Exp: time.Now().Add(time.Hour),
				Iat: time.Now(),
			},
			ExtraClaims: map[string]interface{}{
				"user": "ehe",
			},
		},
	}

	token, err := j.Sign(key)
	if err != nil {
		panic(err)
	}

	fmt.Println(token)

	if err := jwt.Verify(&key.PublicKey, token) ; err != nil {
		panic(err)
	}

	fmt.Println("token verified")
}
```
