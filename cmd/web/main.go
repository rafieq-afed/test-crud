package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	Issuer      string
	ClientID    string
	RedirectURL string
	APIBaseURL  string
	ListenAddr  string
}

func envOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func loadConfig() Config {
	return Config{
		Issuer:      envOrDefault("KEYCLOAK_ISSUER", "http://localhost:8081/realms/crud"),
		ClientID:    envOrDefault("OIDC_CLIENT_ID", "crud-web"),
		RedirectURL: envOrDefault("OIDC_REDIRECT_URL", "http://localhost:8082/callback"),
		APIBaseURL:  envOrDefault("API_BASE_URL", "http://localhost:8080"),
		ListenAddr:  envOrDefault("WEB_ADDR", ":8082"),
	}
}

type Session struct {
	AccessToken string
	IDToken     string
	Username    string
	Expiry      time.Time
}

type sessionStore struct {
	mu    sync.RWMutex
	items map[string]Session
}

func newSessionStore() *sessionStore {
	return &sessionStore{items: make(map[string]Session)}
}

func (s *sessionStore) get(id string) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.items[id]
	return v, ok
}

func (s *sessionStore) set(id string, sess Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[id] = sess
}

func (s *sessionStore) del(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, id)
}

func randB64URL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type tempAuthStore struct {
	mu    sync.Mutex
	items map[string]string // state -> code_verifier
}

func newTempAuthStore() *tempAuthStore {
	return &tempAuthStore{items: make(map[string]string)}
}

func (t *tempAuthStore) put(state, verifier string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.items[state] = verifier
}

func (t *tempAuthStore) pop(state string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.items[state]
	if ok {
		delete(t.items, state)
	}
	return v, ok
}

type Book struct {
	ID     int    `json:"id"`
	Title  string `json:"title"`
	Author string `json:"author"`
}

type server struct {
	cfg        Config
	oauth2     oauth2.Config
	verifier   *oidc.IDTokenVerifier
	endSession string
	sessions   *sessionStore
	tempAuth   *tempAuthStore
	templates  *template.Template
}

func newServer(ctx context.Context, cfg Config) (*server, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}

	var discovery struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&discovery); err != nil {
		return nil, err
	}

	oidcCfg := &oidc.Config{ClientID: cfg.ClientID}
	verifier := provider.Verifier(oidcCfg)

	oauth2Cfg := oauth2.Config{
		ClientID:    cfg.ClientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: cfg.RedirectURL,
		Scopes:      []string{oidc.ScopeOpenID, "profile"},
	}

	tpls, err := template.New("base").Parse(indexHTML + booksHTML)
	if err != nil {
		return nil, err
	}

	return &server{
		cfg:        cfg,
		oauth2:     oauth2Cfg,
		verifier:   verifier,
		endSession: discovery.EndSessionEndpoint,
		sessions:   newSessionStore(),
		tempAuth:   newTempAuthStore(),
		templates:  tpls,
	}, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/callback", s.handleCallback)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/books", s.handleBooksPage)
	mux.HandleFunc("/books/create", s.handleCreateBook)
	return mux
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	sess, _ := s.currentSession(r)
	_ = s.templates.ExecuteTemplate(w, "index", map[string]any{
		"Session": sess,
	})
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randB64URL(24)
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}
	verifier, err := randB64URL(48)
	if err != nil {
		http.Error(w, "failed to generate pkce", http.StatusInternalServerError)
		return
	}
	s.tempAuth.put(state, verifier)

	url := s.oauth2.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", s256Challenge(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state/code", http.StatusBadRequest)
		return
	}
	verifier, ok := s.tempAuth.pop(state)
	if !ok {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	token, err := s.oauth2.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		http.Error(w, "missing id_token", http.StatusBadRequest)
		return
	}
	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "invalid id_token: "+err.Error(), http.StatusBadRequest)
		return
	}

	var claims struct {
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to read claims", http.StatusInternalServerError)
		return
	}

	sid, err := randB64URL(32)
	if err != nil {
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	exp := time.Now().Add(10 * time.Minute)
	if token.Expiry.After(time.Now()) {
		exp = token.Expiry
	}

	s.sessions.set(sid, Session{
		AccessToken: token.AccessToken,
		IDToken:     rawIDToken,
		Username:    claims.PreferredUsername,
		Expiry:      exp,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/books", http.StatusFound)
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var idTokenHint string
	if c, err := r.Cookie("sid"); err == nil && c.Value != "" {
		if sess, ok := s.sessions.get(c.Value); ok {
			idTokenHint = sess.IDToken
		}
		s.sessions.del(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// If available, also log out from Keycloak SSO.
	if strings.TrimSpace(s.endSession) != "" {
		u, err := url.Parse(s.endSession)
		if err == nil {
			q := u.Query()
			if idTokenHint != "" {
				q.Set("id_token_hint", idTokenHint)
			}
			q.Set("post_logout_redirect_uri", "http://localhost:8082/")
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *server) currentSession(r *http.Request) (*Session, bool) {
	c, err := r.Cookie("sid")
	if err != nil || c.Value == "" {
		return nil, false
	}
	sess, ok := s.sessions.get(c.Value)
	if !ok {
		return nil, false
	}
	if time.Now().After(sess.Expiry) {
		return nil, false
	}
	return &sess, true
}

func (s *server) mustSession(w http.ResponseWriter, r *http.Request) (Session, bool) {
	sess, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return Session{}, false
	}
	return *sess, true
}

func (s *server) apiRequest(ctx context.Context, method, path, token string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(s.cfg.APIBaseURL, "/")+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return http.DefaultClient.Do(req)
}

func (s *server) handleBooksPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, ok := s.mustSession(w, r)
	if !ok {
		return
	}

	resp, err := s.apiRequest(r.Context(), http.MethodGet, "/books", sess.AccessToken, nil, "")
	if err != nil {
		http.Error(w, "API error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "API returned "+resp.Status+": "+string(raw), http.StatusBadGateway)
		return
	}

	var books []Book
	if err := json.Unmarshal(raw, &books); err != nil {
		http.Error(w, "failed to decode API response", http.StatusBadGateway)
		return
	}

	_ = s.templates.ExecuteTemplate(w, "books", map[string]any{
		"Session": sess,
		"Books":   books,
	})
}

func (s *server) handleCreateBook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, ok := s.mustSession(w, r)
	if !ok {
		return
	}

	title := strings.TrimSpace(r.FormValue("title"))
	author := strings.TrimSpace(r.FormValue("author"))
	if title == "" {
		http.Error(w, "title is required", http.StatusBadRequest)
		return
	}

	payload, _ := json.Marshal(map[string]string{
		"title":  title,
		"author": author,
	})

	resp, err := s.apiRequest(r.Context(), http.MethodPost, "/books", sess.AccessToken, strings.NewReader(string(payload)), "application/json")
	if err != nil {
		http.Error(w, "API error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		http.Error(w, "API returned "+resp.Status+": "+string(raw), http.StatusBadGateway)
		return
	}

	http.Redirect(w, r, "/books", http.StatusFound)
}

const indexHTML = `
{{define "index"}}
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>CRUD Web</title>
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; max-width: 860px; margin: 40px auto; padding: 0 16px; }
      .card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; }
      a, button { font: inherit; }
      .row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
      .muted { color: #6b7280; }
    </style>
  </head>
  <body>
    <h1>Simple CRUD + Keycloak</h1>
    <div class="card">
      {{if .Session}}
        <div class="row">
          <div>Signed in as <strong>{{.Session.Username}}</strong></div>
          <a href="/books">View books</a>
          <a href="/logout">Logout</a>
        </div>
      {{else}}
        <div class="row">
          <div class="muted">You’re not signed in.</div>
          <a href="/login">Login with Keycloak</a>
        </div>
      {{end}}
    </div>
  </body>
</html>
{{end}}
`

const booksHTML = `
{{define "books"}}
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Books</title>
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; max-width: 860px; margin: 40px auto; padding: 0 16px; }
      .top { display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; align-items: center; }
      .card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; margin-top: 16px; }
      table { width: 100%; border-collapse: collapse; }
      th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid #f0f0f0; }
      input { padding: 10px; border-radius: 10px; border: 1px solid #e5e7eb; width: 100%; }
      button { padding: 10px 12px; border-radius: 10px; border: 1px solid #111827; background: #111827; color: white; cursor: pointer; }
      .muted { color: #6b7280; }
      .grid { display: grid; grid-template-columns: 1fr 1fr auto; gap: 10px; align-items: end; }
      @media (max-width: 720px) { .grid { grid-template-columns: 1fr; } }
      a { color: #111827; }
    </style>
  </head>
  <body>
    <div class="top">
      <div>
        <h1 style="margin:0;">Books</h1>
        <div class="muted">Signed in as <strong>{{.Session.Username}}</strong></div>
      </div>
      <div class="top">
        <a href="/">Home</a>
        <a href="/logout">Logout</a>
      </div>
    </div>

    <div class="card">
      <h2 style="margin-top:0;">Create book (requires crud_admin)</h2>
      <form method="post" action="/books/create">
        <div class="grid">
          <div>
            <label>Title</label><br/>
            <input name="title" placeholder="My Book" required />
          </div>
          <div>
            <label>Author</label><br/>
            <input name="author" placeholder="Author Name" />
          </div>
          <div>
            <button type="submit">Create</button>
          </div>
        </div>
      </form>
      <p class="muted" style="margin-bottom:0;">Tip: login as <code>adminuser/adminuser</code> to create.</p>
    </div>

    <div class="card">
      <h2 style="margin-top:0;">All books</h2>
      <table>
        <thead><tr><th>ID</th><th>Title</th><th>Author</th></tr></thead>
        <tbody>
          {{if .Books}}
            {{range .Books}}
              <tr><td>{{.ID}}</td><td>{{.Title}}</td><td>{{.Author}}</td></tr>
            {{end}}
          {{else}}
            <tr><td colspan="3" class="muted">No books yet.</td></tr>
          {{end}}
        </tbody>
      </table>
    </div>
  </body>
</html>
{{end}}
`

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	srv, err := newServer(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Web listening on", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, srv.routes()); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

