package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/lehigh-university-libraries/rollout/lib/handler"
)

func init() {
	// call getRolloutCmdArgs early to fail on a bad config
	handler.GetRolloutCmdArgs()
}

func main() {
	if os.Getenv("JWKS_URI") == "" {
		slog.Error("JWKS_URI is required. e.g. JWKS_URI=https://gitlab.com/oauth/discovery/keys")
		os.Exit(1)
	}
	if os.Getenv("JWT_AUD") == "" {
		slog.Error("JWT_AUD is required. This needs to be the aud in the JWT you expect this service to handle.")
		os.Exit(1)
	}

	handler.CleanupLock()

	// create a healthcheck with no middleware/auth
	r := mux.NewRouter()
	r.HandleFunc("/healthcheck", handler.HealthCheck).Methods("GET")

	// create the main route with logging and JWT auth middleware
	authRouter := r.PathPrefix("/").Subrouter()
	authRouter.Use(handler.LoggingMiddleware, handler.JWTAuthMiddleware)
	authRouter.HandleFunc("/", handler.Rollout)

	// make sure 404s get logged
	notFoundHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		http.Error(w, "404 Not Found", http.StatusNotFound)
	})
	authRouter.NotFoundHandler = handler.LoggingMiddleware(notFoundHandler)

	port := "8080"
	slog.Info("Server is starting", "port", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		slog.Error("Server failed", "err", err)
		os.Exit(1)

	}
}
