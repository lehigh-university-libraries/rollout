package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/shlex"
	"github.com/lestrrat-go/jwx/jwk"
)

func init() {
	// call getArgs early to fail on a bad config
	getArgs()
}

func main() {
	if os.Getenv("JWKS_URI") == "" {
		slog.Error("JWKS_URI is required. e.g. JWKS_URI=https://gitlab.com/oauth/discovery/keys")
		os.Exit(1)
	}
	if os.Getenv("JWT_AUD") == "" {
		slog.Error("JWT_AUD is required. This needs to be the aud in the JWT you except this service to handle.")
		os.Exit(1)
	}

	http.HandleFunc("/", Rollout)
	slog.Info("Server is running on :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		slog.Error("Unable to start service")
		os.Exit(1)
	}
}

func Rollout(w http.ResponseWriter, r *http.Request) {
	realIp, lastIP := readUserIP(r)

	a := r.Header.Get("Authorization")
	if len(a) < 10 {
		slog.Info("Not auth header", "forwarded-ip", realIp, "lasthop-ip", lastIP)
		http.Error(w, "need authorizaton: bearer xyz header", http.StatusUnauthorized)
		return
	}
	// Assuming "Bearer " prefix
	tokenString := a[7:]

	// Parse and verify the token
	token, err := jwt.Parse(tokenString, ParseToken)
	if err != nil {
		slog.Info("Failed to verify token for", "forwarded-ip", realIp, "lasthop-ip", lastIP, "err", err.Error())
		http.Error(w, "Failed to verify token.", http.StatusUnauthorized)
		return
	}

	if !token.Valid {
		slog.Info("Invalid token for", "forwarded-ip", realIp, "lasthop-ip", lastIP)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	ccStr := os.Getenv("CUSTOM_CLAIMS")
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && ccStr != "" {
		var cc map[string]string
		err = json.Unmarshal([]byte(ccStr), &cc)
		if err != nil {
			slog.Info("Unable to read token claims", "forwarded-ip", realIp, "lasthop-ip", lastIP)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		for k, v := range cc {
			if claims[k] != v {
				slog.Info("Claim doesn't match", "claim", k, "forwarded-ip", realIp, "lasthop-ip", lastIP)
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}
		}
	} else if !ok {
		slog.Info("Unable to read token claims", "forwarded-ip", realIp, "lasthop-ip", lastIP)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	name := os.Getenv("ROLLOUT_CMD")
	if name == "" {
		name = "/bin/bash"
	}
	cmd := exec.Command(name, getArgs()...)

	var stdOut, stdErr bytes.Buffer
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdErr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		slog.Error("Error running", "command", cmd.String(), "stdout", stdOut.String(), "stderr", stdErr.String())
		http.Error(w, "Script execution failed", http.StatusInternalServerError)
		return
	}

	slog.Info("Rollout complete for", "forwarded-ip", realIp, "lasthop-ip", lastIP)
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
		return nil, fmt.Errorf("Unable to fetch JWK set from %s: %v", jwksUri, err)
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

func getArgs() []string {
	args := os.Getenv("ROLLOUT_ARGS")
	if args == "" {
		args = "/rollout.sh"
	}
	rolloutArgs, err := shlex.Split(args)
	if err != nil {
		slog.Error("Error parsing ROLLOUT_ARGS", args, "err", err)
		os.Exit(1)
	}

	return rolloutArgs
}
