//go:build go1.13
// +build go1.13

package keyfunc_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v4"

	"github.com/MicahParks/keyfunc"
)

// TestNewGivenKeyECDSA tests that a generated ECDSA key can be added to the JWKS and create a proper jwt.Keyfunc.
func TestNewGivenKeyECDSA(t *testing.T) {

	// Create the map of given keys.
	givenKeys := make(map[string]keyfunc.GivenKey)
	key, err := addECDSA(givenKeys, testKID)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	// Use the RSA public key to create a JWKS.
	jwks := keyfunc.NewGiven(givenKeys)

	// Create the JWT with the appropriate key ID.
	token := jwt.New(jwt.SigningMethodES256)
	token.Header[kidAttribute] = testKID

	// Sign, parse, and validate the JWT.
	signParseValidate(t, token, key, jwks)
}

// TestNewGivenKeyEdDSA tests that a generated EdDSA key can be added to the JWKS and create a proper jwt.Keyfunc.
func TestNewGivenKeyEdDSA(t *testing.T) {

	// Create the map of given keys.
	givenKeys := make(map[string]keyfunc.GivenKey)
	key, err := addEdDSA(givenKeys, testKID)
	if err != nil {
		t.Errorf(err.Error())
		t.FailNow()
	}

	// Use the RSA public key to create a JWKS.
	jwks := keyfunc.NewGiven(givenKeys)

	// Create the JWT with the appropriate key ID.
	token := jwt.New(jwt.SigningMethodEdDSA)
	token.Header[kidAttribute] = testKID

	// Sign, parse, and validate the JWT.
	signParseValidate(t, token, key, jwks)
}

// addECDSA adds a new ECDSA key to the given keys map.
func addECDSA(givenKeys map[string]keyfunc.GivenKey, kid string) (key *ecdsa.PrivateKey, err error) {

	// Create the ECDSA key.
	if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, fmt.Errorf("failed to create ECDSA key: %w", err)
	}

	// Add the new ECDSA public key to the keys map.
	givenKeys[kid] = keyfunc.NewGivenECDSA(&key.PublicKey)

	return key, nil
}

// addEdDSA adds a new EdDSA key to the given keys map.
func addEdDSA(givenKeys map[string]keyfunc.GivenKey, kid string) (key ed25519.PrivateKey, err error) {

	// Create the ECDSA key.
	var pub ed25519.PublicKey
	if pub, key, err = ed25519.GenerateKey(rand.Reader); err != nil {
		return nil, fmt.Errorf("failed to create ECDSA key: %w", err)
	}

	// Add the new ECDSA public key to the keys map.
	givenKeys[kid] = keyfunc.NewGivenEdDSA(pub)

	return key, nil
}
