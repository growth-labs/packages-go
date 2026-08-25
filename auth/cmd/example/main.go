// Command example runs a minimal net/http OpenAuth consumer.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/growth-labs/packages-go/auth"
)

func main() {
	client, err := auth.New(auth.Config{
		Issuer:         environment("AUTH_ISSUER", "https://auth.fulcrum-labs.com"),
		IssuerInternal: os.Getenv("AUTH_ISSUER_INTERNAL"),
		ClientID:       environment("AUTH_CLIENT_ID", "fulcrum-projects"),
		ClientSecret:   environmentSecret("AUTH_CLIENT_SECRET"),
		Resource:       environment("AUTH_RESOURCE", "http://localhost:4321"),
		CallbackPath:   "/api/auth/callback",
		CookiePrefix:   "example",
		Providers:      []string{"google", "password", "email-code"},
		GatedPaths:     []string{"/private/*"},
		LoginPath:      "/login",
		LogoutPath:     "/logout",
		LogoutRedirect: "/",
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", login(client))
	mux.HandleFunc("/api/auth/callback", client.Callback)
	mux.HandleFunc("/logout", client.Logout)
	mux.HandleFunc("/private/whoami", func(response http.ResponseWriter, request *http.Request) {
		principal, ok := auth.PrincipalFromContext(request.Context())
		if !ok {
			http.Error(response, "Unauthenticated", http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprintf(response, "subject=%s user_id=%s roles=%v\n", principal.Subject, principal.UserID, principal.Roles)
	})
	mux.HandleFunc("/", func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`<a href="/login?provider=google&redirect=/private/whoami">Sign in</a>`))
	})

	server := &http.Server{
		Addr:              environment("ADDR", ":4321"),
		Handler:           client.Middleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("auth example listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func login(client *auth.Client) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		scheme := "https"
		if request.TLS == nil {
			scheme = "http"
		}
		origin := &url.URL{Scheme: scheme, Host: request.Host}
		target, transaction, err := client.Authorize(
			origin,
			request.URL.Query().Get("provider"),
			request.URL.Query().Get("redirect"),
		)
		if err != nil {
			http.Error(response, "Invalid login request", http.StatusBadRequest)
			return
		}
		client.SetTransactionCookies(response, transaction)
		http.Redirect(response, request, target.String(), http.StatusFound)
	}
}

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func environmentSecret(name string) auth.SecretSource {
	if os.Getenv(name) == "" {
		return nil
	}
	return auth.SecretSourceFunc(func(context.Context) (string, error) {
		value := os.Getenv(name)
		if value == "" {
			return "", fmt.Errorf("secret binding is unavailable")
		}
		return value, nil
	})
}
