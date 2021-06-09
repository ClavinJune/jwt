package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"
)

var (
	privateKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
	publicKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA66lyuDmWpCNcVzxk4e5B
vIAQH8uOMfGpjqJ5PP/ax4j74agH10bcTZ3fwDEm5RgOvqE2LwMEAk58aJ2lODGE
0Znr2UwJZE5/GRZ3PzBe7toADUF2mbydoTWDlMdXymaEWNkO1z+Gt0+PUL49N0Z1
n0olGt1lACKaL3iQSUaO+MpchdpBHDMEOLsKd0u/0D+1F8gX+AZJ1tnW7k8OfsWY
fBSYJbNkDtgNeuvebNe3KxPKlMTA5sdY+uxW4CwW9hyhkDIefRP44aC/oENTtH2o
frN9h5QJI+VOB9b1wD06Mf95zevJ7Bgea+RIVw+InuOidz/T+03dbG/9xbEcTpp/
MzR4BhR9kYo+fbTq8V8Tf0QORsvNglFpHLba3lb7B/oYkED3iRZu0ZZ4Qfjs/tJ7
yu5jRfGTh3ZtekM0EKAfbNQtt628WYiE8XOJRrioF/fkPFF6wf9/U+QKK7uodT4+
QLKA21rIeTU9jekjoBP4CtJ1PCjL0YIvlTHki7NFthE4925uvyDc6/h7PCC8laBW
XYp5BNP2nKzAHsdkcM7JB7tH+tJ3rHDMylZWzc/QBbDa/IpTmDmJM7TkNyy0lpRh
EX9sH6TsmZFHHznvvyuvp541kYq1HgrV/ctqYGleI/rDZ0gGZfWDDRRcljycowdc
X+8Pif0iH5szx9OdXyKAtSECAwEAAQ==
-----END PUBLIC KEY-----`
)

func getPrivKey() *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(privateKey))
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	return key
}

func getPublicKey() *rsa.PublicKey {
	block, _ := pem.Decode([]byte(publicKey))
	key, _ := x509.ParsePKIXPublicKey(block.Bytes)
	return key.(*rsa.PublicKey)
}

func TestJWT_Sign(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2021-06-04T17:54:05+07:00")

	rc := RegisteredClaims{
		Iss: "issuer",
		Sub: "subject",
		Aud: []string{"aud1", "aud2"},
		Exp: now,
		Iat: now,
	}

	ec := map[string]interface{}{
		"user": struct{ Name string }{Name: "testing"},
	}

	h := Header{Alg: HeaderAlgRS256, Typ: HeaderTypJWT}
	c := Claims{rc, ec}
	j := JWT{Header: h, Claims: c}

	_, err := j.Sign(getPrivKey())
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerify(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2021-06-04T17:54:05+07:00")

	rc := RegisteredClaims{
		Iss: "issuer",
		Sub: "subject",
		Aud: []string{"aud1", "aud2"},
		Exp: now,
		Iat: now,
	}

	ec := map[string]interface{}{
		"user": struct{ Name string }{Name: "testing"},
	}

	h := Header{Alg: HeaderAlgRS256, Typ: HeaderTypJWT}
	c := Claims{rc, ec}
	j := JWT{Header: h, Claims: c}

	result, err := j.Sign(getPrivKey())
	if err != nil {
		t.Fatal(err)
	}

	if err := Verify(getPublicKey(), result); err != nil {
		t.Fatal(err)
	}
}

func TestFrom(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2021-06-04T17:54:05+07:00")

	rc := RegisteredClaims{
		Iss: "issuer",
		Sub: "subject",
		Aud: []string{"aud1", "aud2"},
		Exp: now,
		Iat: now,
	}

	ec := map[string]interface{}{
		"user": struct{ Name string }{Name: "testing"},
	}

	h := Header{Alg: HeaderAlgRS256, Typ: HeaderTypJWT}
	c := Claims{rc, ec}
	j := JWT{Header: h, Claims: c}

	result, err := j.Sign(getPrivKey())
	if err != nil {
		t.Fatal(err)
	}

	from, err := From(getPublicKey(), result)
	if err != nil {
		return
	}

	fmt.Println(from)
}