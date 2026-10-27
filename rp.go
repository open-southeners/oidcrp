// Package oidcrp is a small, provider-agnostic OpenID Connect relying party:
// authorization-code login with PKCE (S256), a signed stateless state cookie,
// configurable claim mapping, and resource-server token validation (JWT via
// JWKS or RFC 7662 introspection). It uses net/http only.
package oidcrp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Sentinel errors returned (wrapped) by Callback so apps can map them to HTTP codes.
var (
	ErrProviderError  = errors.New("oidcrp: provider returned an error")
	ErrCodeMissing    = errors.New("oidcrp: state and code are required")
	ErrStateMissing   = errors.New("oidcrp: login state cookie missing")
	ErrStateInvalid   = errors.New("oidcrp: login state cookie invalid")
	ErrStateExpired   = errors.New("oidcrp: login state expired")
	ErrStateMismatch  = errors.New("oidcrp: state mismatch")
	ErrExchangeFailed = errors.New("oidcrp: token exchange failed")
	ErrIDTokenMissing = errors.New("oidcrp: id_token missing")
	ErrIDTokenInvalid = errors.New("oidcrp: id_token invalid")
	ErrNonceMismatch  = errors.New("oidcrp: nonce mismatch")
	ErrDiscovery      = errors.New("oidcrp: provider discovery failed")
)

// RP is an OIDC relying party. It is safe for concurrent use and holds no
// per-login state (that lives in a signed cookie), so any instance built from
// the same Config can complete a login started by another.
type RP struct {
	cfg    Config
	client *http.Client
	disc   discovery
	claims ClaimMap
}

// New validates cfg and returns an RP. Provider discovery is lazy.
func New(cfg Config) (*RP, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.IssuerURL = strings.TrimSpace(cfg.IssuerURL)
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	if cfg.CookieName == "" {
		cfg.CookieName = "oidcrp_state"
	}
	if cfg.CookiePath == "" {
		cfg.CookiePath = "/"
	}
	if cfg.StateTTL <= 0 {
		cfg.StateTTL = 10 * time.Minute
	}
	cfg.Scopes = cfg.scopes()
	return &RP{
		cfg:    cfg,
		client: newHTTPClient(cfg.HTTPClient, cfg.IssuerURL, cfg.DiscoveryURL),
		disc:   discovery{issuer: cfg.IssuerURL},
		claims: cfg.Claims.withDefaults(),
	}, nil
}

func (rp *RP) ctx(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, rp.client)
}

func (rp *RP) redirectURL(r *http.Request) string {
	if rp.cfg.RedirectURLFunc != nil {
		return rp.cfg.RedirectURLFunc(r)
	}
	return rp.cfg.RedirectURL
}

func (rp *RP) oauthConfig(p *oidc.Provider, r *http.Request) oauth2.Config {
	return oauth2.Config{
		ClientID:     rp.cfg.ClientID,
		ClientSecret: rp.cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  rp.redirectURL(r),
		Scopes:       rp.cfg.Scopes,
	}
}

func (rp *RP) cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     rp.cfg.CookieName,
		Value:    value,
		Path:     rp.cfg.CookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   rp.cfg.Secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// LoginHandler starts a login: it sets the signed state cookie and redirects
// to the provider. An optional "next" query parameter (same-origin relative
// path only) is returned by Callback as returnTo.
func (rp *RP) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		p, err := rp.disc.provider(rp.ctx(r.Context()))
		if err != nil {
			http.Error(w, "oidc discovery failed", http.StatusServiceUnavailable)
			return
		}
		st := loginState{
			State:    randomToken(32),
			Nonce:    randomToken(32),
			Verifier: randomToken(64),
			Next:     safeNext(r.URL.Query().Get("next")),
			Expires:  time.Now().Add(rp.cfg.StateTTL).Unix(),
		}
		oc := rp.oauthConfig(p, r)
		authURL := oc.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier))
		http.SetCookie(w, rp.cookie(rp.seal(st), int(rp.cfg.StateTTL/time.Second)))
		http.Redirect(w, r, authURL, http.StatusFound)
	})
}

// Callback completes a login. It always clears the state cookie. It returns
// the verified Identity and the validated post-login path (may be empty).
// Failures wrap one of the exported Err* sentinels.
func (rp *RP) Callback(w http.ResponseWriter, r *http.Request) (Identity, string, error) {
	http.SetCookie(w, rp.cookie("", -1))
	w.Header().Set("Cache-Control", "no-store")

	q := r.URL.Query()
	if e := strings.TrimSpace(q.Get("error")); e != "" {
		if d := q.Get("error_description"); d != "" {
			e += ": " + d
		}
		return Identity{}, "", fmt.Errorf("%w: %s", ErrProviderError, e)
	}
	state := strings.TrimSpace(q.Get("state"))
	code := strings.TrimSpace(q.Get("code"))
	if state == "" || code == "" {
		return Identity{}, "", ErrCodeMissing
	}
	c, err := r.Cookie(rp.cfg.CookieName)
	if err != nil || c.Value == "" {
		return Identity{}, "", ErrStateMissing
	}
	st, err := rp.open(c.Value)
	if err != nil {
		return Identity{}, "", err
	}
	if !constEq(st.State, state) {
		return Identity{}, "", ErrStateMismatch
	}

	ctx := rp.ctx(r.Context())
	p, err := rp.disc.provider(ctx)
	if err != nil {
		return Identity{}, "", fmt.Errorf("%w: %v", ErrDiscovery, err)
	}
	oc := rp.oauthConfig(p, r)
	tok, err := oc.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return Identity{}, "", fmt.Errorf("%w: %v", ErrExchangeFailed, err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return Identity{}, "", ErrIDTokenMissing
	}
	verifier := p.Verifier(&oidc.Config{ClientID: rp.cfg.ClientID})
	idt, err := verifier.Verify(ctx, rawID)
	if err != nil {
		return Identity{}, "", fmt.Errorf("%w: %v", ErrIDTokenInvalid, err)
	}
	if !constEq(idt.Nonce, st.Nonce) {
		return Identity{}, "", ErrNonceMismatch
	}
	var raw map[string]any
	if err := idt.Claims(&raw); err != nil {
		return Identity{}, "", fmt.Errorf("%w: %v", ErrIDTokenInvalid, err)
	}
	id := rp.claims.identity(idt.Issuer, idt.Subject, raw)
	id.Tokens = &Tokens{
		IDToken:      rawID,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		Expiry:       tok.Expiry,
	}
	return id, st.Next, nil
}

// CallbackHandler wraps Callback. onLogin is invoked with the verified
// identity (create the session there); onError receives any failure.
func (rp *RP) CallbackHandler(
	onLogin func(w http.ResponseWriter, r *http.Request, id Identity, returnTo string) error,
	onError func(w http.ResponseWriter, r *http.Request, err error),
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, next, err := rp.Callback(w, r)
		if err == nil {
			err = onLogin(w, r, id, next)
		}
		if err != nil {
			onError(w, r, err)
		}
	})
}

// EndSessionURL builds an RP-initiated logout URL from the provider's
// end_session_endpoint. ok is false when the provider does not advertise one
// (or discovery fails).
func (rp *RP) EndSessionURL(idTokenHint, postLogoutRedirectURI string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := rp.disc.provider(rp.ctx(ctx))
	if err != nil {
		return "", false
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if p.Claims(&meta) != nil || meta.EndSession == "" {
		return "", false
	}
	u, err := url.Parse(meta.EndSession)
	if err != nil {
		return "", false
	}
	q := u.Query()
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirectURI)
	}
	u.RawQuery = q.Encode()
	return u.String(), true
}
