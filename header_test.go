package jwt

import (
	"testing"
)

func TestHeader_Encode(t *testing.T) {
	tt := []struct {
		Header Header
		Want   string
	}{{
		Header: Header{},
		Want:   "e30",
	}, {
		Header: Header{
			Alg: HeaderAlgRS256,
			Typ: HeaderTypJWT,
		},
		Want: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
	}}

	for _, test := range tt {
		got, err := test.Header.Encode()
		if err != nil {
			t.Fatal(err)
		}

		if got != test.Want {
			t.Fatalf(`got "%v", want "%v"`, got, test.Want)
		}
	}
}

func TestHeaderFrom(t *testing.T) {
	tt := []struct {
		token string
		want  *Header
	}{{
		token:   "e30",
		want: &Header{},
	}, {
		token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
		want: &Header{
			Alg: HeaderAlgRS256,
			Typ: HeaderTypJWT,
		},
	}}

	for _, test := range tt {
		got, err := HeaderFrom(test.token)
		if err != nil {
			t.Fatal(err)
		}

		if got.Typ != test.want.Typ {
			t.Fatalf(`got "%v", want "%v"`, got, test.want)
		}

		if got.Alg != test.want.Alg {
			t.Fatalf(`got "%v", want "%v"`, got, test.want)
		}
	}
}
