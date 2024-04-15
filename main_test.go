package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

// createJWKS creates a JWKS JSON representation with a single RSA key.
func mockJWKS(pub *rsa.PublicKey, kid string) (string, error) {
	jwks := struct {
		Keys []map[string]interface{} `json:"keys"`
	}{
		Keys: []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": kid,
				"alg": "RS256",
				"n":   encodeBigInt(pub.N),
				"e":   encodeBigInt(big.NewInt(int64(pub.E))),
			},
		},
	}

	jwksJSON, err := json.Marshal(jwks)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWKS: %v", err)
	}
	return string(jwksJSON), nil
}

// GenerateRSAKeys generates and returns RSA private and public keys.
func GenerateRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	// Extract the public key from the private key
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

// encodeBigInt encodes big integers like RSA modulus and exponent to the
// Base64 URL-encoded format used in JWKS.
func encodeBigInt(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

// Set up the mock server
func setupMockJwksServer(pub *rsa.PublicKey, kid string) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		jwks, err := mockJWKS(pub, kid)
		if err != nil {
			log.Fatalf("Unable to generate RSA keys: %v", err)
		}

		_, err = w.Write([]byte(jwks))
		if err != nil {
			log.Fatalf("Unable to generate RSA keys: %v", err)
		}
	})

	return httptest.NewServer(handler)
}

func CreateSignedJWT(kid, aud string, exp int64, privateKey *rsa.PrivateKey) (string, error) {
	// Define the claims of the token. You can add more claims based on your needs.
	claims := jwt.MapClaims{
		"sub": "1234567890",
		"aud": aud,
		"iat": time.Now().Unix(),
		"exp": exp,
	}

	// Create a new token object with the claims and the signing method
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	token.Header["kid"] = kid

	// Sign the token with the private key
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign the token: %v", err)
	}

	return signedToken, nil
}

func TestTokenVerification(t *testing.T) {
	os.Setenv("JWT_AUD", "test-success")

	kid := "no-kidding"
	aud := os.Getenv("JWT_AUD")
	privateKey, publicKey, err := GenerateRSAKeys()
	if err != nil {
		log.Fatalf("Unable to generate RSA keys: %v", err)
	}
	server := setupMockJwksServer(publicKey, kid)
	defer server.Close()

	jwkURL := fmt.Sprintf("%s/oauth/discovery/keys", server.URL)
	os.Setenv("JWKS_URI", jwkURL)

	// make sure valid tokens succeed
	exp := time.Now().Add(time.Hour * 24).Unix()
	jwtToken, err := CreateSignedJWT(kid, aud, exp, privateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our test key: %v", err)
	}
	token, err := jwt.Parse(jwtToken, ParseToken)
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	// make sure invalid kids fail
	jwtToken, err = CreateSignedJWT("just-kidding", aud, exp, privateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our test key: %v", err)
	}
	token, err = jwt.Parse(jwtToken, ParseToken)
	assert.Error(t, err)
	assert.False(t, token.Valid)

	// make sure if we pass a JWT signed by another private key it fails
	badPrivateKey, _, err := GenerateRSAKeys()
	if err != nil {
		t.Fatalf("Unable to generate a new private key")
	}
	jwtToken, err = CreateSignedJWT(kid, aud, exp, badPrivateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our new test key: %v", err)
	}
	token, err = jwt.Parse(jwtToken, ParseToken)
	assert.Error(t, err)
	assert.False(t, token.Valid)

	// make sure expired JWTs fail
	expired := time.Now().Add(time.Hour * -1).Unix()
	jwtToken, err = CreateSignedJWT(kid, aud, expired, privateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our test key: %v", err)
	}
	token, err = jwt.Parse(jwtToken, ParseToken)
	assert.Error(t, err)
	assert.False(t, token.Valid)

	// make sure bad audience JWTs fail
	jwtToken, err = CreateSignedJWT(kid, "different-audience", exp, privateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our test key: %v", err)
	}
	token, err = jwt.Parse(jwtToken, ParseToken)
	assert.Error(t, err)
	assert.False(t, token.Valid)
}
