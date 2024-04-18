package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

var (
	kid, claim, aud string
	privateKey      *rsa.PrivateKey
)

type Test struct {
	name           string
	authHeader     string
	expectedStatus int
	expectedBody   string
	cmdArgs        string
	method         string
	payload        string
}

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
			slog.Error("Unable to generate RSA keys", "err", err)
			os.Exit(1)
		}

		_, err = w.Write([]byte(jwks))
		if err != nil {
			slog.Error("Unable to generate RSA keys", "err", err)
			os.Exit(1)
		}
	})

	return httptest.NewServer(handler)
}

func createMockJwksServer() *httptest.Server {
	var publicKey *rsa.PublicKey
	var err error

	os.Setenv("JWT_AUD", "test-success")
	kid = "no-kidding"
	aud = os.Getenv("JWT_AUD")
	claim = "bar"
	privateKey, publicKey, err = GenerateRSAKeys()
	if err != nil {
		slog.Error("Unable to generate RSA keys", "err", err)
		os.Exit(1)
	}
	testServer := setupMockJwksServer(publicKey, kid)
	os.Setenv("JWKS_URI", fmt.Sprintf("%s/oauth/discovery/keys", testServer.URL))
	return testServer
}

func CreateSignedJWT(kid, aud, claim string, exp int64, privateKey *rsa.PrivateKey) (string, error) {
	// Define the claims of the token. You can add more claims based on your needs.
	claims := jwt.MapClaims{
		"sub": "1234567890",
		"aud": aud,
		"iat": time.Now().Unix(),
		"exp": exp,
		"foo": claim,
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
func createRequest(authHeader, method string, body io.Reader) *http.Request {
	req, _ := http.NewRequest(method, "/", body)
	req.Header.Set("Authorization", authHeader)
	return req
}

// TestRollout tests the Rollout function with various scenarios
func TestRolloutAuth(t *testing.T) {
	testFile := "/tmp/rollout-test.txt"

	// have our test rollout cmd just touch a file
	os.Setenv("ROLLOUT_CMD", "touch")
	os.Setenv("ROLLOUT_ARGS", testFile)

	// make sure the test file doesn't exist
	err := RemoveFileIfExists(testFile)
	if err != nil {
		slog.Error("Unable to cleanup test file", "err", err)
		os.Exit(1)
	}

	s := createMockJwksServer()
	defer s.Close()

	// get a valid token
	exp := time.Now().Add(time.Hour * 1).Unix()
	jwtToken, err := CreateSignedJWT(kid, aud, claim, exp, privateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our test key: %v", err)
	}

	// make sure invalid kids fail
	badKidJwtToken, err := CreateSignedJWT("just-kidding", aud, claim, exp, privateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our test key: %v", err)
	}

	// make sure if we pass a JWT signed by another private key it fails
	badPrivateKey, _, err := GenerateRSAKeys()
	if err != nil {
		t.Fatalf("Unable to generate a new private key")
	}
	badPrivKeyjwtToken, err := CreateSignedJWT(kid, aud, claim, exp, badPrivateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our new test key: %v", err)
	}

	// make sure expired JWTs fail
	expired := time.Now().Add(time.Hour * -1).Unix()
	expiredJwtToken, err := CreateSignedJWT(kid, aud, claim, expired, privateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our test key: %v", err)
	}

	// make sure bad audience JWTs fail
	badAudJwtToken, err := CreateSignedJWT(kid, "different-audience", claim, exp, privateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our test key: %v", err)
	}

	// make sure JWTs with a bad custom claim fail
	badClaimJwtToken, err := CreateSignedJWT(kid, aud, "bad-claim", exp, privateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our test key: %v", err)
	}

	tests := []Test{
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
			name:           "Bad custom claim",
			authHeader:     "Bearer " + badClaimJwtToken,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid token\n",
		},
		{
			name:           "No custom claim",
			authHeader:     "Bearer " + jwtToken,
			expectedStatus: http.StatusOK,
			expectedBody:   "Rollout complete\n",
		},
		{
			name:           "Rollout cmd with quotes parsed correctly",
			authHeader:     "Bearer " + jwtToken,
			expectedStatus: http.StatusOK,
			cmdArgs:        `/tmp/rollout-shlex-test /tmp/"rollout test filename wrapped in quotes"`,
			expectedBody:   "Rollout complete\n",
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
			request := createRequest(tt.authHeader, "GET", nil)
			if tt.name == "No custom claim" {
				os.Setenv("CUSTOM_CLAIMS", "")
			} else {
				os.Setenv("CUSTOM_CLAIMS", `{"foo": "bar"}`)
			}
			if tt.cmdArgs != "" {
				os.Setenv("ROLLOUT_ARGS", tt.cmdArgs)
			}

			Rollout(recorder, request)

			assert.Equal(t, tt.expectedStatus, recorder.Code)
			assert.Equal(t, tt.expectedBody, recorder.Body.String())
		})
	}
	testFiles := []string{
		testFile,
		"/tmp/rollout-shlex-test",
		`/tmp/rollout test filename wrapped in quotes`,
	}
	for _, f := range testFiles {
		// make sure the rollout command actually ran the command
		// which creates the file
		_, err = os.Stat(f)
		if err != nil && os.IsNotExist(err) {
			t.Errorf("The successful test did not create the expected file %s", f)
		}

		// cleanup
		err = RemoveFileIfExists(f)
		if err != nil {
			slog.Error("Unable to cleanup test file", "file", f, "err", err)
			os.Exit(1)
		}
	}
}

func TestRolloutCmdArgs(t *testing.T) {
	os.Setenv("ROLLOUT_CMD", "/bin/bash")
	s := createMockJwksServer()
	defer s.Close()

	// get a valid token
	exp := time.Now().Add(time.Hour * 1).Unix()
	jwtToken, err := CreateSignedJWT(kid, aud, claim, exp, privateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our test key: %v", err)
	}

	payloads := map[string]string{
		"docker-image": "us-docker.pkg.dev-project-interal-image:latest",
		"docker-tag":   "rollout-docker-tag-test",
		"git-branch":   "rollout-git-branch-test",
		"git-repo":     "git@github.com:lehigh-university-libraries-rollout.git",
		"rollout-arg1": "rollout-arg1-test",
		"rollout-arg2": "rollout-arg2-test",
		"rollout-arg3": "rollout-arg3-test",
	}
	for k, v := range payloads {
		var e string
		switch k {
		case "docker-image":
			e = "DOCKER_IMAGE"
		case "docker-tag":
			e = "DOCKER_TAG"
		case "git-branch":
			e = "GIT_BRANCH"
		case "git-repo":
			e = "GIT_REPO"
		case "rollout-arg1":
			e = "ROLLOUT_ARG1"
		case "rollout-arg2":
			e = "ROLLOUT_ARG2"
		case "rollout-arg3":
			e = "ROLLOUT_ARG3"
		}
		tt := Test{
			name:           fmt.Sprintf("%s custom arg passes to rollout.sh", k),
			authHeader:     "Bearer " + jwtToken,
			expectedStatus: http.StatusOK,
			cmdArgs:        fmt.Sprintf(`-c "touch /tmp/$%s"`, e),
			method:         "POST",
			payload:        fmt.Sprintf(`{"%s": "%s"}`, k, v),
			expectedBody:   "Rollout complete\n",
		}
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			method := "POST"
			body := strings.NewReader(tt.payload)
			request := createRequest(tt.authHeader, method, body)
			os.Setenv("ROLLOUT_ARGS", tt.cmdArgs)

			Rollout(recorder, request)

			assert.Equal(t, tt.expectedStatus, recorder.Code)
			assert.Equal(t, tt.expectedBody, recorder.Body.String())
		})
	}

	for _, v := range payloads {
		f := "/tmp/" + v
		// make sure the rollout command actually ran the command
		// which creates the file
		_, err = os.Stat(f)
		if err != nil && os.IsNotExist(err) {
			t.Errorf("The successful test did not create the expected file %s", f)
		}

		// cleanup
		err = RemoveFileIfExists(f)
		if err != nil {
			slog.Error("Unable to cleanup test file", "file", f, "err", err)
			os.Exit(1)
		}
	}
}

func TestBadRolloutCmdArgs(t *testing.T) {
	os.Setenv("ROLLOUT_CMD", "/bin/bash")
	s := createMockJwksServer()
	defer s.Close()

	// get a valid token
	exp := time.Now().Add(time.Hour * 1).Unix()
	jwtToken, err := CreateSignedJWT(kid, aud, claim, exp, privateKey)
	if err != nil {
		t.Fatalf("Unable to create a JWT with our test key: %v", err)
	}

	payloads := []string{
		`{"rollout-arg1": "any;thing"}`,
		`{"rollout-arg1": "any&thing"}`,
		`{"rollout-arg1": "any|thing"}`,
		`{"rollout-arg1": "any$thing"}`,
		`{"rollout-arg1": "any\"thing"}`,
		`{"rollout-arg1": "any\thing"}`,
		`{"rollout-arg1": "any*thing"}`,
		`{"rollout-arg1": "any?thing"}`,
		`{"rollout-arg1": "any[thing"}`,
		`{"rollout-arg1": "any]thing"}`,
		`{"rollout-arg1": "any{thing"}`,
		`{"rollout-arg1": "any}thing"}`,
		`{"rollout-arg1": "any(thing"}`,
		`{"rollout-arg1": "any)thing"}`,
		`{"rollout-arg1": "any<thing"}`,
		`{"rollout-arg1": "any>thing"}`,
		`{"rollout-arg1": "anything!"}`,
		"{\"rollout-arg1\": \"any`thing\"}",
	}
	for _, payload := range payloads {
		tt := Test{
			name:           "Bad custom arg doesn't pass to rollout.sh",
			authHeader:     "Bearer " + jwtToken,
			expectedStatus: http.StatusBadRequest,
			cmdArgs:        `-c "touch /tmp/$ROLLOUT_ARG1"`,
			method:         "POST",
			payload:        payload,
			expectedBody:   "Bad request\n",
		}
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			method := "POST"
			body := strings.NewReader(tt.payload)
			request := createRequest(tt.authHeader, method, body)
			os.Setenv("ROLLOUT_ARGS", tt.cmdArgs)

			Rollout(recorder, request)

			assert.Equal(t, tt.expectedStatus, recorder.Code)
			assert.Equal(t, tt.expectedBody, recorder.Body.String())
		})
	}

	for _, v := range payloads {
		f := "/tmp/" + v
		// make sure the rollout command didn't run the command
		// which creates the file
		_, err = os.Stat(f)
		if err != nil && os.IsNotExist(err) {
			continue
		}
		t.Errorf("The test created a bad file name. Check sanitizing inputs to catch %s", f)

		// cleanup
		err = RemoveFileIfExists(f)
		if err != nil {
			slog.Error("Unable to cleanup test file", "file", f, "err", err)
			os.Exit(1)
		}
	}
}

func RemoveFileIfExists(filePath string) error {
	_, err := os.Stat(filePath)
	if err == nil {
		err := os.Remove(filePath)
		if err != nil {
			return fmt.Errorf("failed to remove file: %v", err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error checking file: %v", err)
	}

	return nil
}
