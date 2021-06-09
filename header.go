package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// HeaderAlg stores algorithm of the jwt
type HeaderAlg string

// HeaderTyp stores type of the jwt, which is JWT
type HeaderTyp string

const (
	HeaderAlgRS256 HeaderAlg = "RS256"

	HeaderTypJWT HeaderTyp = "JWT"
)

// Header stores header component of JWT
type Header struct {
	Alg HeaderAlg `json:"alg,omitempty"`
	Typ HeaderTyp `json:"typ,omitempty"`
}

// HeaderFrom construct Header from encoded token
func HeaderFrom(token string) (*Header, error) {
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("%w, %s", ErrDecodingFailed, err.Error())
	}

	var h *Header
	if err := json.Unmarshal(b, &h) ; err != nil {
		return nil, fmt.Errorf("%w, %s", ErrDecodingFailed, err.Error())
	}

	return h, nil
}

// Encode returns Header in encoded string form
func (h *Header) Encode() (string, error) {
	b, err := json.Marshal(h)

	if err != nil {
		return "", fmt.Errorf("%w, %s", ErrEncodingFailed, err.Error())
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
