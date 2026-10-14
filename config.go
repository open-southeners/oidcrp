package oidcrp

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config configures a relying party (see New).
type Config struct {
	// IssuerURL is the public OIDC issuer (must match the "iss" claim).
	IssuerURL string
	// DiscoveryURL optionally routes server-side calls (discovery, JWKS, token
	// endpoint) to an internal host. Only the host[:port] of IssuerURL is
	// rewritten; scheme and path are preserved.
	DiscoveryURL string

	ClientID     string
	ClientSecret string

	// RedirectURL is the static callback URL. RedirectURLFunc, when set, takes
	// precedence and derives it per request. One of the two is required.
	RedirectURL     string
	RedirectURLFunc func(*http.Request) string

	// Scopes defaults to openid, email, profile; "openid" is always forced first.
	Scopes []string

	// CookieSecret signs the login-state cookie. Required; use 32+ random bytes
	// and share it between all instances of the app.
	CookieSecret []byte
	CookieName   string // default "oidcrp_state"
	CookiePath   string // default "/"
	Secure       bool   // Secure attribute of the state cookie
	StateTTL     time.Duration

	// HTTPClient is used for all provider calls (default: 15s timeout client).
	HTTPClient *http.Client

	Claims ClaimMap
}

// ConfigFromEnv reads a Config from environment variables named
// <prefix>ISSUER_URL, DISCOVERY_URL, CLIENT_ID, CLIENT_SECRET, REDIRECT_URL,
// SCOPES (space separated) plus the claim-map overrides ADMIN_CLAIM,
// ROLES_CLAIM, ROLE_CLAIM, ADMIN_ROLE and ENTITLEMENTS_CLAIM. CookieSecret and
// the other fields must be set by the caller.
func ConfigFromEnv(prefix string) Config {
	get := func(k string) string { return strings.TrimSpace(os.Getenv(prefix + k)) }
	cm := DefaultClaimMap()
	if v := get("ADMIN_CLAIM"); v != "" {
		cm.AdminBoolClaim = v
	}
	if v := get("ROLES_CLAIM"); v != "" {
		cm.RolesClaim = v
	}
	if v := get("ROLE_CLAIM"); v != "" {
		cm.RoleClaim = v
	}
	if v := get("ADMIN_ROLE"); v != "" {
		cm.AdminRole = v
	}
	if v := get("ENTITLEMENTS_CLAIM"); v != "" {
		cm.EntitlementsClaim = v
	}
	return Config{
		IssuerURL:    get("ISSUER_URL"),
		DiscoveryURL: get("DISCOVERY_URL"),
		ClientID:     get("CLIENT_ID"),
		ClientSecret: os.Getenv(prefix + "CLIENT_SECRET"),
		RedirectURL:  get("REDIRECT_URL"),
		Scopes:       strings.Fields(get("SCOPES")),
		Claims:       cm,
	}
}

func (c Config) validate() error {
	switch {
	case strings.TrimSpace(c.IssuerURL) == "":
		return errors.New("oidcrp: IssuerURL is required")
	case strings.TrimSpace(c.ClientID) == "":
		return errors.New("oidcrp: ClientID is required")
	case len(c.CookieSecret) == 0:
		return errors.New("oidcrp: CookieSecret is required")
	case c.RedirectURL == "" && c.RedirectURLFunc == nil:
		return errors.New("oidcrp: RedirectURL or RedirectURLFunc is required")
	}
	return nil
}

func (c Config) scopes() []string {
	out := []string{"openid"}
	if len(c.Scopes) == 0 {
		return append(out, "email", "profile")
	}
	for _, s := range c.Scopes {
		if s != "" && s != "openid" {
			out = append(out, s)
		}
	}
	return out
}

// newHTTPClient builds the client used for provider calls, rewriting the
// issuer host to the discovery host when they differ.
func newHTTPClient(base *http.Client, issuerURL, discoveryURL string) *http.Client {
	var c http.Client
	if base != nil {
		c = *base
	} else {
		c.Timeout = 15 * time.Second
	}
	if discoveryURL = strings.TrimSpace(discoveryURL); discoveryURL != "" {
		from, err1 := url.Parse(issuerURL)
		to, err2 := url.Parse(discoveryURL)
		if err1 == nil && err2 == nil && from.Host != to.Host {
			rt := c.Transport
			if rt == nil {
				rt = http.DefaultTransport
			}
			c.Transport = &hostRewriter{base: rt, from: from.Host, to: to.Host}
		}
	}
	return &c
}

// hostRewriter redirects requests for one host to another, preserving scheme
// and path.
type hostRewriter struct {
	base http.RoundTripper
	from string
	to   string
}

func (t *hostRewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == t.from {
		r2 := req.Clone(req.Context())
		r2.URL.Host = t.to
		return t.base.RoundTrip(r2)
	}
	return t.base.RoundTrip(req)
}
