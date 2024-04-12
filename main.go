package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
)

var (
	gitLabJwksURL = "https://%s/oauth/discovery/keys"
	aud           string
)

func init() {
	domain := os.Getenv("GITLAB_DOMAIN")
	if domain == "" {
		log.Fatal("GITLAB_DOMAIN is required. You could use GITLAB_DOMAIN=gitlab.com")
	}
	gitLabJwksURL = fmt.Sprintf(gitLabJwksURL, domain)

	aud = os.Getenv("JWT_AUD")
	if aud == "" {
		log.Fatal("JWT_AUD is required. This needs to be the aud in the JWT you except this service to handle.")
	}

}

func main() {
	ctx := context.Background()

	// Fetch the JWKS from GitLab
	set, err := jwk.Fetch(ctx, gitLabJwksURL)
	if err != nil {
		fmt.Printf("Failed to fetch JWKS: %v\n", err)
		return
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Check audience claim
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				return nil, fmt.Errorf("error retrieving claims from token")
			}
			if !claims.VerifyAudience(aud, true) {
				return nil, fmt.Errorf("invalid audience. Expected: %s", aud)
			}

			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("expecting JWT header to have string 'kid'")
			}

			// Find the appropriate key in JWKS
			key, ok := set.LookupKeyID(kid)
			if !ok {
				return nil, fmt.Errorf("unable to find key '%s'", kid)
			}

			var pubkey interface{}
			if err := key.Raw(&pubkey); err != nil {
				return nil, fmt.Errorf("failed to get raw key: %v", err)
			}

			return pubkey, nil
		})

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

		// TODO make this more customizable
		// but for now this fills the need
		cmd := exec.Command("/bin/bash", "/rollout.sh")

		var stdErr bytes.Buffer
		cmd.Stderr = &stdErr
		cmd.Env = os.Environ()
		if err := cmd.Run(); err != nil {
			log.Printf("Error running %s command: %s", cmd.String(), stdErr.String())
			http.Error(w, "Script execution failed", http.StatusInternalServerError)
			return
		}

		log.Println("Rollout complete for", realIp, ",", lastIP)
		fmt.Fprintln(w, "Rollout complete")
	})

	fmt.Println("Server is running on http://localhost:8080/")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Unable to start service")
	}
}

func readUserIP(r *http.Request) (string, string) {
	realIP := r.Header.Get("X-Real-Ip")
	lastIP := r.RemoteAddr
	if realIP == "" {
		realIP = r.Header.Get("X-Forwarded-For")
	}
	return realIP, lastIP
}
