package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrEncodingFailed  = errors.New("jwt: failed to encode jwt")
	ErrDecodingFailed  = errors.New("jwt: failed to decode base64")
	ErrSigningFailed   = errors.New("jwt: failed to sign jwt")
	ErrVerifyingFailed = errors.New("jwt: failed to verify token")
)

type JWT struct {
	token string
	Header Header
	Claims Claims
}

func (j *JWT) Sign(key *rsa.PrivateKey) (string, error) {
	h, err := j.Header.Encode()
	if err != nil {
		return "", err
	}

	c, err := j.Claims.Encode()
	if err != nil {
		return "", err
	}

	hashed := sha256.Sum256([]byte(h + "." + c))

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("%w, %s", ErrSigningFailed, err.Error())
	}

	return fmt.Sprintf("%v.%v.%v", h, c, base64.RawURLEncoding.EncodeToString(signature)), nil
}

func Verify(key *rsa.PublicKey, token string) error {
	splitToken := strings.Split(token, ".")
	hc := splitToken[0] + "." + splitToken[1]
	hashed := sha256.Sum256([]byte(hc))

	b, err := base64.RawURLEncoding.DecodeString(splitToken[2])
	if err != nil {
		return fmt.Errorf("%w, %s", ErrDecodingFailed, err.Error())
	}

	err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], b)
	if err != nil {
		return fmt.Errorf("%w, %s", ErrVerifyingFailed, err.Error())
	}

	return nil
}

func From(key *rsa.PublicKey, token string) (*JWT, error) {
	if err := Verify(key, token) ; err != nil {
		return nil, err
	}

	splitToken := strings.Split(token, ".")

	h, err := HeaderFrom(splitToken[0])
	if err != nil {
		return nil, err
	}

	c, err := ClaimsFrom(splitToken[1])
	if err != nil {
		return nil, err
	}

	return &JWT{
		token:  token,
		Header: *h,
		Claims: *c,
	}, nil
}