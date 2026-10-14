package oidcrp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// TokenConfig configures a TokenValidator (OAuth 2.0 resource server).
type TokenConfig struct {
	IssuerURL    string
	DiscoveryURL string // optional internal host, see Config.DiscoveryURL
	// Audience is the resource identifier tokens must be issued for (required).
	Audience string

	// IntrospectionURL enables RFC 7662 validation of opaque tokens.
	IntrospectionURL          string
	IntrospectionClientID     string
	IntrospectionClientSecret string

	HTTPClient *http.Client
	Claims     ClaimMap

	// Test/advanced seams. Verifier wins over KeySet; when either is set no
	// discovery is performed for JWT verification. Audience is still enforced
	// by the validator, so the verifier must skip its own client-ID check.
	Verifier *oidc.IDTokenVerifier
	KeySet   oidc.KeySet
}

// TokenInfo is a validated access token.
type TokenInfo struct {
	Identity
	Audiences []string
	Scopes    []string
}

// TokenValidator validates Bearer access tokens.
type TokenValidator struct {
	cfg    TokenConfig
	client *http.Client
	disc   discovery
	claims ClaimMap
}

// NewTokenValidator validates cfg and returns a TokenValidator.
func NewTokenValidator(cfg TokenConfig) (*TokenValidator, error) {
	if strings.TrimSpace(cfg.Audience) == "" {
		return nil, errors.New("oidcrp: Audience is required")
	}
	if strings.TrimSpace(cfg.IssuerURL) == "" && cfg.Verifier == nil && cfg.KeySet == nil {
		return nil, errors.New("oidcrp: IssuerURL is required")
	}
	cfg.IssuerURL = strings.TrimSpace(cfg.IssuerURL)
	return &TokenValidator{
		cfg:    cfg,
		client: newHTTPClient(cfg.HTTPClient, cfg.IssuerURL, cfg.DiscoveryURL),
		disc:   discovery{issuer: cfg.IssuerURL},
		claims: cfg.Claims.withDefaults(),
	}, nil
}

// Validate verifies raw and enforces subject and exact audience.
//
// A three-segment token is treated as a JWT and verified against the JWKS; a
// failure is final and never falls back to introspection. Anything else is
// introspected (an error if introspection is not configured).
func (v *TokenValidator) Validate(ctx context.Context, raw string) (TokenInfo, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return TokenInfo{}, errors.New("oidcrp: empty token")
	}
	var (
		info TokenInfo
		err  error
	)
	if len(strings.Split(raw, ".")) == 3 {
		info, err = v.validateJWT(ctx, raw)
	} else {
		info, err = v.introspect(ctx, raw)
	}
	if err != nil {
		return TokenInfo{}, err
	}
	if strings.TrimSpace(info.Subject) == "" {
		return TokenInfo{}, errors.New("oidcrp: token has no subject claim")
	}
	ok := false
	for _, a := range info.Audiences {
		if a == v.cfg.Audience {
			ok = true
			break
		}
	}
	if !ok {
		return TokenInfo{}, errors.New("oidcrp: token audience does not match this resource")
	}
	return info, nil
}

func (v *TokenValidator) verifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	if v.cfg.Verifier != nil {
		return v.cfg.Verifier, nil
	}
	conf := &oidc.Config{SkipClientIDCheck: true}
	if v.cfg.KeySet != nil {
		return oidc.NewVerifier(v.cfg.IssuerURL, v.cfg.KeySet, conf), nil
	}
	p, err := v.disc.provider(oidc.ClientContext(ctx, v.client))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscovery, err)
	}
	return p.Verifier(conf), nil
}

func (v *TokenValidator) validateJWT(ctx context.Context, raw string) (TokenInfo, error) {
	ver, err := v.verifier(ctx)
	if err != nil {
		return TokenInfo{}, err
	}
	idt, err := ver.Verify(oidc.ClientContext(ctx, v.client), raw)
	if err != nil {
		return TokenInfo{}, err
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return TokenInfo{}, fmt.Errorf("oidcrp: parsing jwt claims: %w", err)
	}
	return v.info(idt.Issuer, idt.Subject, claims, ""), nil
}

func (v *TokenValidator) info(iss, sub string, claims map[string]any, emailFallback string) TokenInfo {
	id := v.claims.identity(iss, sub, claims)
	if id.Email == "" {
		id.Email = strings.TrimSpace(emailFallback)
	}
	return TokenInfo{Identity: id, Audiences: stringList(claims["aud"]), Scopes: scopesOf(claims)}
}

func scopesOf(c map[string]any) []string {
	if s, ok := c["scope"].(string); ok {
		return strings.Fields(s)
	}
	return stringList(c["scp"])
}

func (v *TokenValidator) introspect(ctx context.Context, raw string) (TokenInfo, error) {
	if v.cfg.IntrospectionURL == "" {
		return TokenInfo{}, errors.New("oidcrp: token is not a JWT and introspection is not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.cfg.IntrospectionURL,
		strings.NewReader(url.Values{"token": {raw}}.Encode()))
	if err != nil {
		return TokenInfo{}, fmt.Errorf("oidcrp: building introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(v.cfg.IntrospectionClientID, v.cfg.IntrospectionClientSecret)
	client := v.cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return TokenInfo{}, fmt.Errorf("oidcrp: introspection request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return TokenInfo{}, fmt.Errorf("oidcrp: introspection endpoint returned status %d", resp.StatusCode)
	}
	var claims map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return TokenInfo{}, fmt.Errorf("oidcrp: decoding introspection response: %w", err)
	}
	if active, _ := claims["active"].(bool); !active {
		return TokenInfo{}, errors.New("oidcrp: token is not active")
	}
	return v.info(stringClaim(claims, "iss"), stringClaim(claims, "sub"), claims, stringClaim(claims, "username")), nil
}
