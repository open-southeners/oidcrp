package oidcrp

import (
	"context"
	"strings"
	"testing"
)

const testAud = "https://api.example/mcp"

func newValidator(t *testing.T, f *fakeProvider, introspect bool) *TokenValidator {
	t.Helper()
	cfg := TokenConfig{IssuerURL: f.issuer, DiscoveryURL: f.srv.URL, Audience: testAud}
	if introspect {
		cfg.IntrospectionURL = f.srv.URL + "/introspect"
		cfg.IntrospectionClientID = "rs"
		cfg.IntrospectionClientSecret = "rs-secret"
	}
	v, err := NewTokenValidator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestValidateJWT(t *testing.T) {
	f := newFakeProvider(t, "")
	v := newValidator(t, f, false)
	ti, err := v.Validate(context.Background(), f.accessToken(map[string]any{
		"email": "a@b.c", "scope": "read write", "roles": []string{"admin"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if ti.Subject != "user-1" || ti.Issuer != f.issuer || ti.Email != "a@b.c" || !ti.IsAdmin ||
		len(ti.Audiences) != 1 || strings.Join(ti.Scopes, ",") != "read,write" {
		t.Errorf("%+v", ti)
	}
}

func TestValidateAudience(t *testing.T) {
	f := newFakeProvider(t, "")
	v := newValidator(t, f, false)
	ctx := context.Background()
	if _, err := v.Validate(ctx, f.accessToken(map[string]any{"aud": "https://other"})); err == nil {
		t.Error("wrong aud accepted")
	}
	if _, err := v.Validate(ctx, f.accessToken(map[string]any{"aud": nil})); err == nil {
		t.Error("missing aud accepted")
	}
	if _, err := v.Validate(ctx, f.accessToken(map[string]any{"aud": testAud})); err != nil {
		t.Errorf("string aud: %v", err)
	}
	if _, err := v.Validate(ctx, f.accessToken(map[string]any{"aud": []string{"x", testAud}})); err != nil {
		t.Errorf("array aud: %v", err)
	}
	if _, err := v.Validate(ctx, f.accessToken(map[string]any{"aud": []string{testAud + "/x"}})); err == nil {
		t.Error("prefix aud accepted")
	}
}

func TestValidateMissingSub(t *testing.T) {
	f := newFakeProvider(t, "")
	v := newValidator(t, f, false)
	if _, err := v.Validate(context.Background(), f.accessToken(map[string]any{"sub": nil})); err == nil {
		t.Error("missing sub accepted")
	}
}

func TestTamperedJWTNoIntrospectionFallback(t *testing.T) {
	f := newFakeProvider(t, "")
	f.introBody = map[string]any{"active": true, "sub": "user-1", "aud": testAud}
	v := newValidator(t, f, true)
	tok := f.accessToken(nil)
	parts := strings.Split(tok, ".")
	bad := parts[0] + "." + parts[1] + "." + "AAAA" + parts[2][4:]
	before := f.hits
	if _, err := v.Validate(context.Background(), bad); err == nil {
		t.Fatal("tampered JWT accepted")
	}
	if f.introAuth != "" {
		t.Error("introspection was called for a JWT")
	}
	_ = before
	// Expired JWT is also final.
	if _, err := v.Validate(context.Background(), f.accessToken(map[string]any{"exp": 1})); err == nil {
		t.Error("expired JWT accepted")
	}
	if f.introAuth != "" {
		t.Error("introspection called for expired JWT")
	}
}

func TestIntrospection(t *testing.T) {
	f := newFakeProvider(t, "")
	v := newValidator(t, f, true)
	ctx := context.Background()

	f.introBody = map[string]any{"active": true, "sub": "u", "iss": f.issuer, "aud": []string{testAud}, "username": "ana@x.io", "scope": "a b"}
	ti, err := v.Validate(ctx, "opaque-token")
	if err != nil {
		t.Fatal(err)
	}
	if ti.Email != "ana@x.io" || ti.Subject != "u" || len(ti.Scopes) != 2 {
		t.Errorf("%+v", ti)
	}
	if f.introAuth != "rs:rs-secret" {
		t.Errorf("basic auth %q", f.introAuth)
	}

	f.introBody = map[string]any{"active": false, "sub": "u", "aud": testAud}
	if _, err := v.Validate(ctx, "opaque-token"); err == nil {
		t.Error("inactive accepted")
	}

	f.introStatus = 500
	f.introBody = map[string]any{"active": true, "sub": "u", "aud": testAud}
	if _, err := v.Validate(ctx, "opaque-token"); err == nil {
		t.Error("non-200 accepted")
	}
	f.introStatus = 200

	f.introBody = map[string]any{"active": true, "aud": testAud}
	if _, err := v.Validate(ctx, "opaque-token"); err == nil {
		t.Error("missing sub accepted")
	}
	f.introBody = map[string]any{"active": true, "sub": "u", "aud": "other"}
	if _, err := v.Validate(ctx, "opaque-token"); err == nil {
		t.Error("wrong aud accepted")
	}
}

func TestIntrospectionUnconfigured(t *testing.T) {
	f := newFakeProvider(t, "")
	v := newValidator(t, f, false)
	if _, err := v.Validate(context.Background(), "opaque-token"); err == nil {
		t.Error("opaque token accepted without introspection")
	}
}

func TestTokenConfigValidation(t *testing.T) {
	if _, err := NewTokenValidator(TokenConfig{IssuerURL: "https://i"}); err == nil {
		t.Error("missing audience accepted")
	}
	if _, err := NewTokenValidator(TokenConfig{Audience: "a"}); err == nil {
		t.Error("missing issuer accepted")
	}
}
