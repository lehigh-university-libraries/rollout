package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
)

func main() {
	if os.Getenv("JWKS_URI") == "" {
		log.Fatal("JWKS_URI is required. e.g. JWKS_URI=https://gitlab.com/oauth/discovery/keys")
	}
	if os.Getenv("JWT_AUD") == "" {
		log.Fatal("JWT_AUD is required. This needs to be the aud in the JWT you except this service to handle.")
	}

	http.HandleFunc("/", Rollout)
	log.Println("Server is running on :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Unable to start service")
	}
}

func Rollout(w http.ResponseWriter, r *http.Request) {
	realIp, lastIP := readUserIP(r)

	a := r.Header.Get("Authorization")
	if len(a) < 10 {
		log.Println("Not auth header for", realIp, ",", lastIP)
		http.Error(w, "need authorizaton: bearer xyz header", http.StatusUnauthorized)
		return
	}
	// Assuming "Bearer " prefix
	tokenString := a[7:]

	// Parse and verify the token
	token, err := jwt.Parse(tokenString, ParseToken)
	if err != nil {
		log.Println("Failed to verify token for", realIp, ",", lastIP, err.Error())
		http.Error(w, "Failed to verify token.", http.StatusUnauthorized)
		return
	}

	if !token.Valid {
		log.Println("Invalid token for", realIp, ",", lastIP, err.Error())
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	name := os.Getenv("ROLLOUT_CMD")
	if name == "" {
		name = "/bin/bash"
	}
	args := os.Getenv("ROLLOUT_ARGS")
	if args == "" {
		args = "/rollout.sh"
	}
	cmd := exec.Command(name, strings.Split(args, " ")...)

	var stdOut, stdErr bytes.Buffer
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdErr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		log.Printf("Error running %s command: %s", cmd.String(), stdOut.String())
		log.Printf("stderr: %s", stdErr.String())
		http.Error(w, "Script execution failed", http.StatusInternalServerError)
		return
	}

	log.Println("Rollout complete for", realIp, ",", lastIP)
	fmt.Fprintln(w, "Rollout complete")
}

func ParseToken(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	// Check audience claim
	aud := os.Getenv("JWT_AUD")
	taud, err := token.Claims.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("could not get aud claim: %v", err)
	}
	if !strInSlice(aud, taud) {
		return nil, fmt.Errorf("invalid audience. Expected: %s", aud)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("expecting JWT header to have string 'kid'")
	}

	ctx := context.Background()
	jwksUri := os.Getenv("JWKS_URI")
	jwksSet, err := jwk.Fetch(ctx, jwksUri)
	if err != nil {
		log.Fatalf("Unable to fetch JWK set from %s: %v", jwksUri, err)
	}
	// Find the appropriate key in JWKS
	key, ok := jwksSet.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("unable to find key '%s'", kid)
	}

	var pubkey interface{}
	if err := key.Raw(&pubkey); err != nil {
		return nil, fmt.Errorf("failed to get raw key: %v", err)
	}

	return pubkey, nil
}

func readUserIP(r *http.Request) (string, string) {
	realIP := r.Header.Get("X-Real-Ip")
	lastIP := r.RemoteAddr
	if realIP == "" {
		realIP = r.Header.Get("X-Forwarded-For")
	}
	return realIP, lastIP
}

func strInSlice(e string, s []string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
