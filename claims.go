package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// RegisteredClaims stores standard claims of JWT
type RegisteredClaims struct {
	Iss string
	Sub string
	Aud []string
	Exp time.Time
	Iat time.Time
}

// Claims stores RegisteredClaims and ExtraClaims
type Claims struct {
	RegisteredClaims
	ExtraClaims map[string]interface{}
}

// ClaimsFrom construct Claims from encoded token
func ClaimsFrom(token string) (*Claims, error) {
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("%w, %s", ErrDecodingFailed, err.Error())
	}

	m := make(map[string]interface{})
	if err := json.Unmarshal(b, &m) ; err != nil {
		return nil, fmt.Errorf("%w, %s", ErrDecodingFailed, err.Error())
	}

	c := Claims{
		RegisteredClaims: RegisteredClaims{},
		ExtraClaims:      make(map[string]interface{}),
	}
	for k, v := range m {
		switch k {
		case "iss":
			c.Iss = v.(string)
		case "sub":
			c.Sub = v.(string)
		case "aud":
			b, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("%w, %s", ErrDecodingFailed, err.Error())
			}
			if err := json.Unmarshal(b, &c.Aud) ; err != nil {
				return nil, fmt.Errorf("%w, %s", ErrDecodingFailed, err.Error())
			}
		case "exp":
			c.Exp = time.Unix(int64(v.(float64)), 0)
		case "iat":
			c.Iat = time.Unix(int64(v.(float64)), 0)
		default:
			c.ExtraClaims[k] = v
		}
	}

	return &c, nil
}

// Encode returns Header in encoded string form
func (c Claims) Encode() (string, error) {
	finalClaims := c.getAllClaimsMap()

	b, err := json.Marshal(finalClaims)

	if err != nil {
		return "", fmt.Errorf("%w, %s", ErrEncodingFailed, err.Error())
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// getAllClaimsMap merges RegisteredClaims and ExtraClaims
func (c Claims) getAllClaimsMap() map[string]interface{} {
	finalClaims := make(map[string]interface{})

	if c.Iss != "" {
		finalClaims["iss"] = c.Iss
	}

	if c.Sub != "" {
		finalClaims["sub"] = c.Sub
	}

	if c.Aud != nil {
		finalClaims["aud"] = c.Aud
	}

	if !c.Exp.IsZero() {
		finalClaims["exp"] = c.Exp.Unix()
	}

	if !c.Iat.IsZero() {
		finalClaims["iat"] = c.Iat.Unix()
	}

	for k, v := range c.ExtraClaims {
		finalClaims[k] = v
	}

	return finalClaims
}
