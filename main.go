package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
)

var (
	gitLabJwksURL = "https://%s/oauth/discovery/keys"
)

func init() {
	domain := os.Getenv("GITLAB_DOMAIN")
	if domain == "" {
		log.Fatal("GITLAB_DOMAIN is required. You could use GITLAB_DOMAIN=gitlab.com")
	}

	gitLabJwksURL = fmt.Sprintf(gitLabJwksURL, domain)
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
		tokenString := r.Header.Get("Authorization")[7:] // Assuming "Bearer " prefix

		// Parse and verify the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
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
			http.Error(w, "Failed to verify token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		fmt.Fprintln(w, "Token is valid")
	})

	fmt.Println("Server is running on http://localhost:8080/")
	http.ListenAndServe(":8080", nil)
}
