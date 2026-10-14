package oidcrp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

const (
	testClient = "client-1"
	testSecret = "s3cret"
)

type authCode struct {
	challenge string
	nonce     string
}

// fakeProvider is an httptest OIDC provider.
type fakeProvider struct {
	t      *testing.T
	srv    *httptest.Server
	key    *rsa.PrivateKey
	issuer string

	mu     sync.Mutex
	codes  map[string]authCode
	hits   int
	claims map[string]any // extra id_token claims
	// nonceOverride replaces the nonce in issued id_tokens when non-empty.
	nonceOverride string

	introStatus int
	introBody   map[string]any
	introAuth   string
}

func newFakeProvider(t *testing.T, issuer string) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeProvider{t: t, key: key, codes: map[string]authCode{}, issuer: issuer, introStatus: 200}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/jwks", f.jwks)
	mux.HandleFunc("/token", f.token)
	mux.HandleFunc("/introspect", f.introspect)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits++
		f.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	if f.issuer == "" {
		f.issuer = f.srv.URL
	}
	return f
}

func (f *fakeProvider) discovery(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                f.issuer,
		"authorization_endpoint":                f.issuer + "/authorize",
		"token_endpoint":                        f.issuer + "/token",
		"jwks_uri":                              f.issuer + "/jwks",
		"end_session_endpoint":                  f.issuer + "/logout",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (f *fakeProvider) jwks(w http.ResponseWriter, r *http.Request) {
	e := big.NewInt(int64(f.key.E)).Bytes()
	json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
		"n": b64(f.key.N.Bytes()), "e": b64(e),
	}}})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (f *fakeProvider) sign(claims map[string]any) string {
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	in := b64(h) + "." + b64(p)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		f.t.Fatal(err)
	}
	return in + "." + b64(sig)
}

// accessToken issues a signed JWT access token with the given overrides.
func (f *fakeProvider) accessToken(over map[string]any) string {
	c := map[string]any{
		"iss": f.issuer, "sub": "user-1", "aud": "https://api.example/mcp",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return f.sign(c)
}

// issueCode simulates the authorize endpoint for the redirect Location.
// challengeOverride, when set, replaces the received code_challenge.
func (f *fakeProvider) issueCode(loc *url.URL, challengeOverride string) string {
	q := loc.Query()
	ch := q.Get("code_challenge")
	if challengeOverride != "" {
		ch = challengeOverride
	}
	if q.Get("code_challenge_method") != "S256" {
		f.t.Fatalf("code_challenge_method = %q", q.Get("code_challenge_method"))
	}
	code := "code-" + randomToken(8)
	f.mu.Lock()
	f.codes[code] = authCode{challenge: ch, nonce: q.Get("nonce")}
	f.mu.Unlock()
	return code
}

func (f *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	f.mu.Lock()
	ac, ok := f.codes[r.PostForm.Get("code")]
	extra := map[string]any{}
	for k, v := range f.claims {
		extra[k] = v
	}
	nonceOverride := f.nonceOverride
	f.mu.Unlock()
	bad := func(msg string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": msg})
	}
	if !ok {
		bad("unknown code")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if b64(sum[:]) != ac.challenge {
		bad("pkce verifier mismatch")
		return
	}
	f.mu.Lock()
	delete(f.codes, r.PostForm.Get("code"))
	f.mu.Unlock()
	nonce := ac.nonce
	if nonceOverride != "" {
		nonce = nonceOverride
	}
	claims := map[string]any{
		"iss": f.issuer, "sub": "user-1", "aud": testClient, "nonce": nonce,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"email": "ana@example.com", "email_verified": true, "name": "Ana",
	}
	for k, v := range extra {
		claims[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
		"id_token": f.sign(claims),
	})
}

func (f *fakeProvider) introspect(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, p, _ := r.BasicAuth()
	f.introAuth = u + ":" + p
	w.WriteHeader(f.introStatus)
	json.NewEncoder(w).Encode(f.introBody)
}
