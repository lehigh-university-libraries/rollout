package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type RolloutPayload struct {
	DockerImage string `json:"docker-image" env:"DOCKER_IMAGE"`
	DockerTag   string `json:"docker-tag" env:"DOCKER_TAG"`
	GitRepo     string `json:"git-repo" env:"GIT_REPO"`
	GitBranch   string `json:"git-branch" env:"GIT_BRANCH"`
	Arg1        string `json:"rollout-arg1" env:"ROLLOUT_ARG1"`
	Arg2        string `json:"rollout-arg2" env:"ROLLOUT_ARG2"`
	Arg3        string `json:"rollout-arg3" env:"ROLLOUT_ARG3"`
}

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

// LoggingMiddleware logs incoming HTTP requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		statusWriter := &statusRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}
		next.ServeHTTP(statusWriter, r)
		duration := time.Since(start)
		slog.Info("Incoming request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", statusWriter.statusCode,
			"duration", duration,
			"client_ip", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write([]byte("ok"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		slog.Error("Unable to write for healthcheck", "err", err)
	}
}

// JWTAuthMiddleware validates a JWT token and adds claims to the context
func JWTAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := r.Header.Get("Authorization")
		if a == "" || !strings.HasPrefix(strings.ToLower(a), "bearer ") {
			http.Error(w, "Missing Authorization header", http.StatusBadRequest)
			return
		}

		tokenString := a[7:]
		err := verifyJWT(tokenString)
		if err != nil {
			slog.Error("JWT verification failed", "err", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func verifyJWT(tokenString string) error {
	keySet, err := fetchJWKS()
	if err != nil {
		return fmt.Errorf("unable to fetch JWKS: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKeySet(keySet),
		jwt.WithVerify(true),
		jwt.WithContext(ctx),
	)
	if err != nil {
		return fmt.Errorf("unable to parse token: %v", err)
	}

	if err := validateClaims(token); err != nil {
		return fmt.Errorf("unable to validate claims: %v", err)
	}

	return nil
}

// validateClaims checks if the claims match the expected values
func validateClaims(token jwt.Token) error {
	ccStr := os.Getenv("CUSTOM_CLAIMS")
	expectedClaims := make(map[string]string)
	if ccStr != "" {
		err := json.Unmarshal([]byte(ccStr), &expectedClaims)
		if err != nil {
			return fmt.Errorf("error decoding custom claims: %v", err)
		}
	}
	expectedClaims["aud"] = os.Getenv("JWT_AUD")

	for key, expectedValue := range expectedClaims {
		value, ok := token.Get(key)
		if !ok {
			return fmt.Errorf("missing claim: %s", key)
		}

		switch v := value.(type) {
		case string:
			if !strings.EqualFold(v, expectedValue) {
				return fmt.Errorf("invalid value for claim %s: %s", key, v)
			}
		case []string:
			if !strInSlice(expectedValue, v) {
				return fmt.Errorf("invalid value for claim %s: %s", key, v)
			}
		default:
			return fmt.Errorf("unsupported claim type for %s: %T", key, value)
		}
	}

	return nil
}

// fetchJWKS fetches the JSON Web Key Set (JWKS) from the given URI
func fetchJWKS() (jwk.Set, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	jwksURI := os.Getenv("JWKS_URI")
	return jwk.Fetch(ctx, jwksURI)
}

func strInSlice(e string, s []string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
