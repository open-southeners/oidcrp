package oidcrp

import (
	"strings"
	"time"
)

// ClaimMap names the claims the library reads when building an Identity.
// Empty fields fall back to the defaults from DefaultClaimMap. The defaults
// follow Unikia ID conventions but every name can be overridden to match any
// provider (Keycloak "groups", custom entitlement claims, ...).
type ClaimMap struct {
	// AdminBoolClaim is a boolean claim that, when true, grants admin.
	AdminBoolClaim string
	// RolesClaim is a string or array claim holding role names.
	RolesClaim string
	// RoleClaim is a single-role (string or array) claim, merged into Roles.
	RoleClaim string
	// AdminRole is the role name that grants admin (case-insensitive).
	AdminRole string
	// EntitlementsClaim is a string or array claim listing product entitlements.
	EntitlementsClaim string
	// EmailClaim and NameClaim name the profile claims.
	EmailClaim string
	NameClaim  string
}

// DefaultClaimMap returns the Unikia ID default claim names.
func DefaultClaimMap() ClaimMap {
	return ClaimMap{
		AdminBoolClaim:    "is_admin",
		RolesClaim:        "roles",
		RoleClaim:         "role",
		AdminRole:         "admin",
		EntitlementsClaim: "authorized_apps",
		EmailClaim:        "email",
		NameClaim:         "name",
	}
}

func (c ClaimMap) withDefaults() ClaimMap {
	d := DefaultClaimMap()
	if c.AdminBoolClaim == "" {
		c.AdminBoolClaim = d.AdminBoolClaim
	}
	if c.RolesClaim == "" {
		c.RolesClaim = d.RolesClaim
	}
	if c.RoleClaim == "" {
		c.RoleClaim = d.RoleClaim
	}
	if c.AdminRole == "" {
		c.AdminRole = d.AdminRole
	}
	if c.EntitlementsClaim == "" {
		c.EntitlementsClaim = d.EntitlementsClaim
	}
	if c.EmailClaim == "" {
		c.EmailClaim = d.EmailClaim
	}
	if c.NameClaim == "" {
		c.NameClaim = d.NameClaim
	}
	return c
}

// Identity is the provider-agnostic view of an authenticated principal.
type Identity struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	IsAdmin       bool
	Roles         []string
	Entitlements  []string
	// Raw holds every claim of the verified token.
	Raw map[string]any
	// Tokens holds the tokens issued at login. It is only set by the login
	// callback; identities from a validated bearer token leave it nil.
	Tokens *Tokens
}

// Tokens are the tokens returned by the provider's token endpoint at login.
type Tokens struct {
	// IDToken is the raw, verified ID token. Keep it to pass as the
	// id_token_hint of EndSessionURL; many providers (Ory Hydra among them)
	// only honour post_logout_redirect_uri when a hint is given.
	IDToken string
	// AccessToken and RefreshToken allow calling APIs on the user's behalf.
	// RefreshToken is empty unless the offline_access scope was granted.
	AccessToken  string
	RefreshToken string
	// Expiry is when AccessToken expires (zero if the provider did not say).
	Expiry time.Time
}

// HasEntitlement reports whether the identity holds the entitlement (exact match).
func (i Identity) HasEntitlement(e string) bool {
	for _, v := range i.Entitlements {
		if v == e {
			return true
		}
	}
	return false
}

// HasRole reports whether the identity holds the role (case-insensitive).
func (i Identity) HasRole(r string) bool {
	for _, v := range i.Roles {
		if strings.EqualFold(v, r) {
			return true
		}
	}
	return false
}

// identity maps raw claims into an Identity. cm must already have defaults applied.
func (c ClaimMap) identity(issuer, subject string, raw map[string]any) Identity {
	id := Identity{Issuer: issuer, Subject: subject, Raw: raw}
	id.Email = strings.TrimSpace(stringClaim(raw, c.EmailClaim))
	id.Name = strings.TrimSpace(stringClaim(raw, c.NameClaim))
	if v, ok := raw["email_verified"].(bool); ok {
		id.EmailVerified = v
	}
	id.Roles = stringList(raw[c.RolesClaim])
	for _, r := range stringList(raw[c.RoleClaim]) {
		if !id.HasRole(r) {
			id.Roles = append(id.Roles, r)
		}
	}
	id.Entitlements = stringList(raw[c.EntitlementsClaim])
	if b, ok := raw[c.AdminBoolClaim].(bool); ok && b {
		id.IsAdmin = true
	}
	if id.HasRole(c.AdminRole) {
		id.IsAdmin = true
	}
	return id
}

func stringClaim(raw map[string]any, key string) string {
	s, _ := raw[key].(string)
	return s
}

// stringList accepts a string or an array of strings (non-strings are skipped).
func stringList(v any) []string {
	switch t := v.(type) {
	case string:
		if t = strings.TrimSpace(t); t != "" {
			return []string{t}
		}
	case []string:
		return append([]string(nil), t...)
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}
