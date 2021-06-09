package jwt

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestClaims_Encode(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2021-06-04T17:54:05+07:00")

	tt := []struct {
		Claims Claims
		Want   string
	}{{
		Claims: Claims{},
		Want:   "e30",
	}, {
		Claims: Claims{
			RegisteredClaims: RegisteredClaims{
				Iss: "issuer",
				Sub: "subject",
				Aud: []string{"aud1", "aud2"},
				Exp: now,
				Iat: now,
			},
			ExtraClaims: map[string]interface{}{
				"user": struct {
					Name string
				}{
					Name: "testing",
				},
			},
		},
		Want: "eyJhdWQiOlsiYXVkMSIsImF1ZDIiXSwiZXhwIjoxNjIyODA0MDQ1LCJpYXQiOjE2MjI4MDQwNDUsImlzcyI6Imlzc3VlciIsInN1YiI6InN1YmplY3QiLCJ1c2VyIjp7Ik5hbWUiOiJ0ZXN0aW5nIn19",
	}}

	for _, test := range tt {
		got, err := test.Claims.Encode()
		if err != nil {
			t.Fatal(err)
		}

		if got != test.Want {
			t.Fatalf(`got "%v", want "%v"`, got, test.Want)
		}
	}
}

func TestClaimsFrom(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2021-06-04T17:54:05+07:00")

	tt := []struct {
		token string
		want  Claims
	}{{
		token: "e30",
		want:  Claims{},
	}, {
		token: "eyJhdWQiOlsiYXVkMSIsImF1ZDIiXSwiZXhwIjoxNjIyODA0MDQ1LCJpYXQiOjE2MjI4MDQwNDUsImlzcyI6Imlzc3VlciIsInN1YiI6InN1YmplY3QiLCJ1c2VyIjp7Ik5hbWUiOiJ0ZXN0aW5nIn19",
		want: Claims{
			RegisteredClaims: RegisteredClaims{
				Iss: "issuer",
				Sub: "subject",
				Aud: []string{"aud1", "aud2"},
				Exp: now,
				Iat: now,
			},
			ExtraClaims: map[string]interface{}{
				"user": struct {
					Name string
				}{
					Name: "testing",
				},
			},
		},
	}}

	for _, test := range tt {
		got, err := ClaimsFrom(test.token)
		if err != nil {
			t.Fatal(err)
		}

		if got.Iss != test.want.Iss {
			t.Fatalf(`got "%v", want "%v"`, got, test.want)
		}

		if got.Sub != test.want.Sub {
			t.Fatalf(`got "%v", want "%v"`, got, test.want)
		}

		if got.Exp != test.want.Exp {
			t.Fatalf(`got "%v", want "%v"`, got.Exp, test.want.Exp)
		}

		if got.Iat != test.want.Iat {
			t.Fatalf(`got "%v", want "%v"`, got, test.want)
		}

		if !reflect.DeepEqual(got.Aud, test.want.Aud) {
			t.Fatalf(`got "%v", want "%v"`, got, test.want)
		}

		if len(got.ExtraClaims) != len(test.want.ExtraClaims) {
			fmt.Println(got.ExtraClaims, test.want.ExtraClaims)
			t.Fatalf(`got "%v", want "%v"`, got, test.want)
		}
	}
}
