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

// Utility function to create a request with an Authorization header
func createRequest(authHeader string) *http.Request {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", authHeader)
	return req
}

// TestRollout tests the Rollout function with various scenarios
func TestRollout(t *testing.T) {
	testFile := "/tmp/rollout-test.txt"
	os.Setenv("ROLLOUT_CMD", "touch")
	os.Setenv("ROLLOUT_ARGS", testFile)

	// make sure the test file doesn't exist
	err := RemoveFileIfExists(testFile)
	if err != nil {
		log.Fatalf("Unable to cleanup test file: %v", err)
	}
	defer RemoveFileIfExists(testFile)

	// mock the JWKS server response
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

	// get a valid token
	exp := time.Now().Add(time.Hour * 1).Unix()
	jwtToken, err := CreateSignedJWT(kid, aud, exp, privateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our test key: %v", err)
	}

	// make sure invalid kids fail
	badKidJwtToken, err := CreateSignedJWT("just-kidding", aud, exp, privateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our test key: %v", err)
	}

	// make sure if we pass a JWT signed by another private key it fails
	badPrivateKey, _, err := GenerateRSAKeys()
	if err != nil {
		t.Fatalf("Unable to generate a new private key")
	}
	badPrivKeyjwtToken, err := CreateSignedJWT(kid, aud, exp, badPrivateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our new test key: %v", err)
	}

	// make sure expired JWTs fail
	expired := time.Now().Add(time.Hour * -1).Unix()
	expiredJwtToken, err := CreateSignedJWT(kid, aud, expired, privateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our test key: %v", err)
	}

	// make sure bad audience JWTs fail
	badAudJwtToken, err := CreateSignedJWT(kid, "different-audience", exp, privateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our test key: %v", err)
	}

	// Define test cases
	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "No Authorization Header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "need authorizaton: bearer xyz header\n",
		},
		{
			name:           "Invalid Token",
			authHeader:     "Bearer invalidtoken",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Failed to verify token.\n",
		},
		{
			name:           "Bad kid Token",
			authHeader:     "Bearer " + badKidJwtToken,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Failed to verify token.\n",
		},
		{
			name:           "Signed from wrong JWKS Token",
			authHeader:     "Bearer " + badPrivKeyjwtToken,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Failed to verify token.\n",
		},
		{
			name:           "Expired Token",
			authHeader:     "Bearer " + expiredJwtToken,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Failed to verify token.\n",
		},
		{
			name:           "Bad aud Token",
			authHeader:     "Bearer " + badAudJwtToken,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Failed to verify token.\n",
		},
		{
			name:           "Valid Token and Successful Command",
			authHeader:     "Bearer " + jwtToken,
			expectedStatus: http.StatusOK,
			expectedBody:   "Rollout complete\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := createRequest(tt.authHeader)

			Rollout(recorder, request)

			assert.Equal(t, tt.expectedStatus, recorder.Code)
			assert.Equal(t, tt.expectedBody, recorder.Body.String())
		})
	}

	// make sure the rollout command actually ran the command
	_, err = os.Stat(testFile)
	if err != nil && os.IsNotExist(err) {
		t.Errorf("The successful test did not create the expected file")
	}

}

func RemoveFileIfExists(filePath string) error {
	_, err := os.Stat(filePath)
	if err == nil {
		err := os.Remove(filePath)
		if err != nil {
			return fmt.Errorf("failed to remove file: %v", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("error checking file: %v", err)
	}

	return nil
}
