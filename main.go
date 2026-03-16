package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

type Book struct {
	ID     int    `json:"id"`
	Title  string `json:"title"`
	Author string `json:"author"`
}

type authConfig struct {
	issuer  string
	jwksURL string
}

type bookStore struct {
	mu    sync.RWMutex
	next  int
	items map[int]Book
}

func newBookStore() *bookStore {
	return &bookStore{
		next:  1,
		items: make(map[int]Book),
	}
}

func (s *bookStore) listBooks(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	books := make([]Book, 0, len(s.items))
	for _, b := range s.items {
		books = append(books, b)
	}

	writeJSON(w, http.StatusOK, books)
}

func (s *bookStore) createBook(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Title  string `json:"title"`
		Author string `json:"author"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(input.Title) == "" {
		http.Error(w, "title is required", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	book := Book{
		ID:     s.next,
		Title:  input.Title,
		Author: input.Author,
	}
	s.items[book.ID] = book
	s.next++

	writeJSON(w, http.StatusCreated, book)
}

func (s *bookStore) getBook(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(r)
	if !ok {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	book, exists := s.items[id]
	if !exists {
		http.NotFound(w, r)
		return
	}

	writeJSON(w, http.StatusOK, book)
}

func (s *bookStore) updateBook(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(r)
	if !ok {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	var input struct {
		Title  *string `json:"title"`
		Author *string `json:"author"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	book, exists := s.items[id]
	if !exists {
		http.NotFound(w, r)
		return
	}

	if input.Title != nil {
		book.Title = *input.Title
	}
	if input.Author != nil {
		book.Author = *input.Author
	}

	s.items[id] = book

	writeJSON(w, http.StatusOK, book)
}

func (s *bookStore) deleteBook(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(r)
	if !ok {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.items[id]; !exists {
		http.NotFound(w, r)
		return
	}

	delete(s.items, id)
	w.WriteHeader(http.StatusNoContent)
}

func parseIDParam(r *http.Request) (int, bool) {
	// Expect paths like /books/{id}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		return 0, false
	}
	idStr := parts[1]
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Println("error writing JSON:", err)
	}
}

func envOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func loadAuthConfig() authConfig {
	issuer := envOrDefault("KEYCLOAK_ISSUER", "http://localhost:8081/realms/crud")
	jwksURL := envOrDefault("KEYCLOAK_JWKS_URL", strings.TrimRight(issuer, "/")+"/protocol/openid-connect/certs")
	return authConfig{issuer: issuer, jwksURL: jwksURL}
}

type tokenClaims struct {
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	jwt.RegisteredClaims
}

func (c tokenClaims) hasRole(role string) bool {
	for _, r := range c.RealmAccess.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func parseAndValidateToken(r *http.Request, jwks keyfunc.Keyfunc, cfg authConfig) (tokenClaims, error) {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if authz == "" || !strings.HasPrefix(authz, "Bearer ") {
		return tokenClaims{}, errors.New("missing bearer token")
	}
	raw := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
	if raw == "" {
		return tokenClaims{}, errors.New("missing bearer token")
	}

	var claims tokenClaims
	token, err := jwt.ParseWithClaims(raw, &claims, jwks.Keyfunc)
	if err != nil {
		return tokenClaims{}, err
	}
	if !token.Valid {
		return tokenClaims{}, errors.New("invalid token")
	}
	if claims.Issuer != cfg.issuer {
		return tokenClaims{}, errors.New("invalid issuer")
	}
	if claims.ExpiresAt == nil {
		return tokenClaims{}, errors.New("missing exp")
	}
	if time.Now().After(claims.ExpiresAt.Time) {
		return tokenClaims{}, errors.New("token expired")
	}

	return claims, nil
}

func requireRoles(jwks keyfunc.Keyfunc, cfg authConfig, anyOf ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			claims, err := parseAndValidateToken(r, jwks, cfg)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			for _, role := range anyOf {
				if claims.hasRole(role) {
					next(w, r)
					return
				}
			}
			http.Error(w, "forbidden", http.StatusForbidden)
		}
	}
}

func main() {
	store := newBookStore()

	cfg := loadAuthConfig()
	ctx := context.Background()
	jwks, err := keyfunc.NewDefaultCtx(ctx, []string{cfg.jwksURL})
	if err != nil {
		log.Fatal(err)
	}

	readAuth := requireRoles(jwks, cfg, "crud_user", "crud_admin")
	writeAuth := requireRoles(jwks, cfg, "crud_admin")

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	http.HandleFunc("/books", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			readAuth(store.listBooks)(w, r)
		case http.MethodPost:
			writeAuth(store.createBook)(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/books/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			readAuth(store.getBook)(w, r)
		case http.MethodPut, http.MethodPatch:
			writeAuth(store.updateBook)(w, r)
		case http.MethodDelete:
			writeAuth(store.deleteBook)(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	addr := ":8080"
	log.Println("Server listening on", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}

