package jjwt_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/jjwt"
)

// key is the decoded jwt.base64-secret from application.yml.
var key = mustDecode("ZmQ0ZGI5NjQ0MDQwY2I4MjMxY2Y3ZmI3MjdhN2ZmMjNhODViOTg1ZGE0NTBjMGM4NDA5NzYxMjdjOWMwYWRmZTBlZjlhNGY3ZTg4Y2U3YTE1ODVkZDU5Y2Y3OGYwZWE1NzUzNWQ2YjFjZDc0NGMxZWU2MmQ3MjY1NzJmNTE0MzI=")

func mustDecode(s string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return decoded
}

// TestSignProducesTheOriginalsBytes is the strongest check in the suite: it
// pins a whole token minted by the unmodified Java application. Reproducing it
// requires the header to omit "typ", the claims to be ordered sub, auth, exp,
// and the key to be the base64-decoded bytes rather than the base64 text.
func TestSignProducesTheOriginalsBytes(t *testing.T) {
	tests := []struct {
		name  string
		claim jjwt.Claims
		want  string
	}{
		{
			name:  "user",
			claim: jjwt.Claims{Subject: "user", Auth: "ROLE_USER", Expiration: time.Unix(1787657181, 0)},
			want:  "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyIiwiYXV0aCI6IlJPTEVfVVNFUiIsImV4cCI6MTc4NzY1NzE4MX0.ZA3Zknm4d6BS4ZVEB_AmCrAr9Y161hm9o9sUvIro4E5WJb65hLs54GaN3bhuNIEXYQM_r3hZrMVzRsW_I-2Emw",
		},
		{
			name:  "admin, authorities sorted into the auth claim",
			claim: jjwt.Claims{Subject: "admin", Auth: "ROLE_ADMIN,ROLE_USER", Expiration: time.Unix(1787657182, 0)},
			want:  "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImF1dGgiOiJST0xFX0FETUlOLFJPTEVfVVNFUiIsImV4cCI6MTc4NzY1NzE4Mn0.hiHAUknDcAlznxlmNfZrI7SDE8ROz558d8HAhgdXIuoZxP_bDKYgk55HGWlq3xlcPW3v70Wx2sKpKqOYvGCbug",
		},
		{
			name:  "rememberMe, thirty hours instead of twenty-four",
			claim: jjwt.Claims{Subject: "admin", Auth: "ROLE_ADMIN,ROLE_USER", Expiration: time.Unix(1787678782, 0)},
			want:  "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImF1dGgiOiJST0xFX0FETUlOLFJPTEVfVVNFUiIsImV4cCI6MTc4NzY3ODc4Mn0.gaDTejbCFySVCu97dY5T7FZyhhb_IqYUrwO6nVUw0nZnetUcN2KVUodTgsWSiSAtTCvegrIVMPtZ8O-m1aMDZA",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := jjwt.Sign(test.claim, key); got != test.want {
				t.Errorf("Sign() =\n%s\nwant\n%s", got, test.want)
			}
		})
	}
}

func TestSignHeaderHasNoTypMember(t *testing.T) {
	token := jjwt.Sign(jjwt.Claims{Subject: "user", Expiration: time.Unix(1, 0)}, key)

	header, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	if string(header) != `{"alg":"HS512"}` {
		t.Errorf("header = %s, want %s", header, `{"alg":"HS512"}`)
	}
}

func TestSignClaimsAreOrderedSubAuthExp(t *testing.T) {
	token := jjwt.Sign(jjwt.Claims{Subject: "user", Auth: "ROLE_USER", Expiration: time.Unix(42, 0)}, key)

	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	if want := `{"sub":"user","auth":"ROLE_USER","exp":42}`; string(payload) != want {
		t.Errorf("payload = %s, want %s", payload, want)
	}
}

func TestParseRoundTrip(t *testing.T) {
	now := time.Unix(1000, 0)
	claims := jjwt.Claims{Subject: "user", Auth: "ROLE_USER", Expiration: time.Unix(2000, 0)}

	parsed, err := jjwt.Parse(jjwt.Sign(claims, key), key, now)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.Subject != claims.Subject || parsed.Auth != claims.Auth || !parsed.Expiration.Equal(claims.Expiration) {
		t.Errorf("Parse() = %+v, want %+v", parsed, claims)
	}
}

// TestParseFailureCategories covers the four categories TokenProvider
// distinguishes, each of which produces a different log line.
func TestParseFailureCategories(t *testing.T) {
	now := time.Unix(1000, 0)
	valid := jjwt.Sign(jjwt.Claims{Subject: "user", Auth: "ROLE_USER", Expiration: time.Unix(2000, 0)}, key)

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{name: "empty token", token: "", want: jjwt.ErrIllegalArgument},
		{name: "blank token", token: "   ", want: jjwt.ErrIllegalArgument},
		{name: "too few segments", token: "a.b", want: jjwt.ErrMalformed},
		{name: "too many segments", token: "a.b.c.d", want: jjwt.ErrMalformed},
		{name: "undecodable header", token: "!!.bb.cc", want: jjwt.ErrMalformed},
		{name: "header that is not JSON", token: "YWJj.bb.cc", want: jjwt.ErrMalformed},
		{name: "unsigned token", token: "eyJhbGciOiJIUzUxMiJ9.e30.", want: jjwt.ErrUnsupported},
		{name: "unknown algorithm", token: base64URL(`{"alg":"none"}`) + ".e30.cc", want: jjwt.ErrUnsupported},
		{name: "asymmetric algorithm", token: base64URL(`{"alg":"RS256"}`) + ".e30.cc", want: jjwt.ErrUnsupported},
		{name: "tampered signature", token: valid[:len(valid)-1] + flip(valid[len(valid)-1]), want: jjwt.ErrSignature},
		{
			name:  "expired token",
			token: jjwt.Sign(jjwt.Claims{Subject: "user", Auth: "ROLE_USER", Expiration: time.Unix(500, 0)}, key),
			want:  jjwt.ErrExpired,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := jjwt.Parse(test.token, key, now)
			if !errors.Is(err, test.want) {
				t.Errorf("Parse(%q) error = %v, want %v", test.token, err, test.want)
			}
		})
	}
}

// TestParseRejectsAnotherKey confirms the signature is actually checked.
func TestParseRejectsAnotherKey(t *testing.T) {
	token := jjwt.Sign(jjwt.Claims{Subject: "user", Expiration: time.Unix(2000, 0)}, key)

	_, err := jjwt.Parse(token, []byte("a different key entirely"), time.Unix(1000, 0))

	if !errors.Is(err, jjwt.ErrSignature) {
		t.Errorf("Parse() error = %v, want %v", err, jjwt.ErrSignature)
	}
}

// TestParseChecksTheSignatureBeforeExpiry matches jjwt's ordering: a token that
// is both expired and forged reports the forgery.
func TestParseChecksTheSignatureBeforeExpiry(t *testing.T) {
	expired := jjwt.Sign(jjwt.Claims{Subject: "user", Expiration: time.Unix(500, 0)}, key)
	forged := expired[:len(expired)-1] + flip(expired[len(expired)-1])

	_, err := jjwt.Parse(forged, key, time.Unix(1000, 0))

	if !errors.Is(err, jjwt.ErrSignature) {
		t.Errorf("Parse() error = %v, want %v", err, jjwt.ErrSignature)
	}
}

func base64URL(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func flip(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}
