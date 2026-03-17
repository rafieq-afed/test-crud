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

type Student struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type authConfig struct {
	issuer  string
	jwksURL string
}

type studentStore struct {
	mu    sync.RWMutex
	next  int
	items map[int]Student
}

func newStudentStore() *studentStore {
	return &studentStore{
		next:  1,
		items: make(map[int]Student),
	}
}

func (s *studentStore) listStudents(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Student, 0, len(s.items))
	for _, st := range s.items {
		out = append(out, st)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *studentStore) createStudent(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(input.Name) == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	st := Student{
		ID:    s.next,
		Name:  input.Name,
		Email: input.Email,
	}
	s.items[st.ID] = st
	s.next++

	writeJSON(w, http.StatusCreated, st)
}

func (s *studentStore) getStudent(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(r)
	if !ok {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	st, exists := s.items[id]
	if !exists {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *studentStore) updateStudent(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(r)
	if !ok {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	var input struct {
		Name  *string `json:"name"`
		Email *string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	st, exists := s.items[id]
	if !exists {
		http.NotFound(w, r)
		return
	}
	if input.Name != nil {
		st.Name = *input.Name
	}
	if input.Email != nil {
		st.Email = *input.Email
	}
	s.items[id] = st
	writeJSON(w, http.StatusOK, st)
}

func (s *studentStore) deleteStudent(w http.ResponseWriter, r *http.Request) {
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
	// Expect paths like /students/{id}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		return 0, false
	}
	id, err := strconv.Atoi(parts[1])
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
	store := newStudentStore()

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

	http.HandleFunc("/students", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			readAuth(store.listStudents)(w, r)
		case http.MethodPost:
			writeAuth(store.createStudent)(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/students/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			readAuth(store.getStudent)(w, r)
		case http.MethodPut, http.MethodPatch:
			writeAuth(store.updateStudent)(w, r)
		case http.MethodDelete:
			writeAuth(store.deleteStudent)(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	addr := envOrDefault("STUDENT_ADDR", ":8083")
	log.Println("Student API listening on", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}

