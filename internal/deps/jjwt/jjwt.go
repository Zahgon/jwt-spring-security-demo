// Package jjwt reproduces the slice of io.jsonwebtoken (jjwt 0.10.6) that the
// original application depends on: HS512-signed compact JWS, and the exception
// taxonomy TokenProvider switches on when a token fails to parse.
//
// The encoding is reproduced rather than delegated because its exact bytes are
// part of the contract. jjwt writes the header as {"alg":"HS512"} with no "typ"
// member, and serialises claims from a LinkedHashMap, so they appear in the
// order the builder set them: sub, auth, exp. Those bytes are what gets signed,
// so a JSON encoder that sorts members — as Go's does for maps — produces a
// different signature for the same claims, and the result cannot interoperate
// with the original.
package jjwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"strconv"
	"strings"
	"time"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/deps/jackson"
)

// The five failure categories TokenProvider distinguishes. They map one-to-one
// onto the exceptions it catches: SignatureException and MalformedJwtException
// share a catch block, ExpiredJwtException, UnsupportedJwtException and
// IllegalArgumentException have their own.
var (
	ErrSignature       = errors.New("JWT signature does not match locally computed signature")
	ErrMalformed       = errors.New("JWT strings must contain exactly 2 period characters")
	ErrExpired         = errors.New("JWT expired")
	ErrUnsupported     = errors.New("signed Claims JWSs are not supported")
	ErrIllegalArgument = errors.New("JWT String argument cannot be null or empty")
)

// Claims are the three members the application puts in a token. jjwt would
// carry an arbitrary map; only these are ever used, and fixing them as struct
// fields is what pins their serialisation order.
type Claims struct {
	Subject    string
	Auth       string
	Expiration time.Time
}

const headerHS512 = `{"alg":"HS512"}`

var enc = base64.RawURLEncoding

// Sign builds the compact serialisation of claims signed with HMAC-SHA512
// under key, which must already be the raw key bytes (jjwt's
// Keys.hmacShaKeyFor takes decoded bytes, not a base64 string).
func Sign(claims Claims, key []byte) string {
	var payload strings.Builder
	payload.WriteString(`{"sub":`)
	payload.Write(jackson.EncodeString(claims.Subject))
	payload.WriteString(`,"auth":`)
	payload.Write(jackson.EncodeString(claims.Auth))
	payload.WriteString(`,"exp":`)
	payload.WriteString(strconv.FormatInt(claims.Expiration.Unix(), 10))
	payload.WriteString(`}`)

	signingInput := enc.EncodeToString([]byte(headerHS512)) + "." + enc.EncodeToString([]byte(payload.String()))
	return signingInput + "." + enc.EncodeToString(sign(sha512.New, key, signingInput))
}

// Parse verifies a compact JWS against key and returns its claims. now is the
// instant expiry is judged against. Failures are reported as one of the
// sentinel errors above, matching how jjwt classifies them.
func Parse(token string, key []byte, now time.Time) (Claims, error) {
	if strings.TrimSpace(token) == "" {
		return Claims{}, ErrIllegalArgument
	}

	parts := strings.Split(token, ".")
	switch {
	case len(parts) == 3 && parts[2] == "":
		// An unsecured JWT: parseClaimsJws refuses it rather than accepting an
		// unverified payload.
		return Claims{}, ErrUnsupported
	case len(parts) != 3:
		return Claims{}, ErrMalformed
	}

	headerJSON, err := enc.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return Claims{}, ErrMalformed
	}

	newHash, ok := hmacAlgorithms[header.Alg]
	if !ok {
		return Claims{}, ErrUnsupported
	}

	signature, err := enc.DecodeString(parts[2])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	expected := sign(newHash, key, parts[0]+"."+parts[1])
	if !hmac.Equal(signature, expected) {
		return Claims{}, ErrSignature
	}

	payloadJSON, err := enc.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrMalformed
	}
	var body struct {
		Sub  string `json:"sub"`
		Auth string `json:"auth"`
		Exp  *int64 `json:"exp"`
	}
	if err := json.Unmarshal(payloadJSON, &body); err != nil {
		return Claims{}, ErrMalformed
	}

	claims := Claims{Subject: body.Sub, Auth: body.Auth}
	if body.Exp != nil {
		claims.Expiration = time.Unix(*body.Exp, 0)
		// jjwt validates expiry only after the signature has been accepted.
		if !claims.Expiration.After(now) {
			return Claims{}, ErrExpired
		}
	}
	return claims, nil
}

// jjwt verifies whichever HMAC algorithm the header names, using the configured
// key; a token signed with a different HMAC variant therefore fails on the
// signature rather than on the algorithm.
var hmacAlgorithms = map[string]func() hash.Hash{
	"HS256": sha256.New,
	"HS384": sha512.New384,
	"HS512": sha512.New,
}

func sign(newHash func() hash.Hash, key []byte, signingInput string) []byte {
	mac := hmac.New(newHash, key)
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}
