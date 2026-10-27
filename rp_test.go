package oidcrp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var testSecretBytes = []byte("0123456789abcdef0123456789abcdef")

func testConfig(f *fakeProvider) Config {
	return Config{
		IssuerURL:    f.issuer,
		DiscoveryURL: f.srv.URL,
		ClientID:     testClient,
		ClientSecret: testSecret,
		RedirectURL:  "https://app.example/auth/callback",
		CookieSecret: testSecretBytes,
	}
}

func newTestRP(t *testing.T, cfg Config) *RP {
	t.Helper()
	rp, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

func login(t *testing.T, rp *RP, target string) (*url.URL, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	rp.LoginHandler().ServeHTTP(w, httptest.NewRequest("GET", target, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("login status %d: %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	var ck *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "oidcrp_state" {
			ck = c
		}
	}
	if ck == nil {
		t.Fatal("no state cookie")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("missing no-store")
	}
	return loc, ck
}

func callback(rp *RP, ck *http.Cookie, state, code string) (Identity, string, error, *httptest.ResponseRecorder) {
	target := "/cb?state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(code)
	r := httptest.NewRequest("GET", target, nil)
	if ck != nil {
		r.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	id, next, err := rp.Callback(w, r)
	return id, next, err, w
}

func flow(t *testing.T, f *fakeProvider, rp *RP, target string) (Identity, string, error) {
	loc, ck := login(t, rp, target)
	code := f.issueCode(loc, "")
	id, next, err, _ := callback(rp, ck, loc.Query().Get("state"), code)
	return id, next, err
}

func TestHappyPath(t *testing.T) {
	f := newFakeProvider(t, "")
	rp := newTestRP(t, testConfig(f))
	loc, ck := login(t, rp, "/login?next=/templates")
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" {
		t.Fatalf("bad authorize url %s", loc)
	}
	if q.Get("scope") != "openid email profile" {
		t.Errorf("scope = %q", q.Get("scope"))
	}
	if !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode || ck.MaxAge != 600 {
		t.Errorf("cookie attrs: %+v", ck)
	}
	code := f.issueCode(loc, "")
	id, next, err, w := callback(rp, ck, q.Get("state"), code)
	if err != nil {
		t.Fatal(err)
	}
	if next != "/templates" || id.Subject != "user-1" || id.Email != "ana@example.com" || !id.EmailVerified || id.Name != "Ana" || id.Issuer != f.issuer {
		t.Errorf("identity %+v next %q", id, next)
	}
	if id.IsAdmin {
		t.Error("unexpected admin")
	}
	if id.Tokens == nil || id.Tokens.IDToken == "" || id.Tokens.AccessToken == "" {
		t.Errorf("login tokens not returned: %+v", id.Tokens)
	}
	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == "oidcrp_state" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("state cookie not cleared")
	}
}

func TestStatelessAcrossInstances(t *testing.T) {
	f := newFakeProvider(t, "")
	cfg := testConfig(f)
	a, b := newTestRP(t, cfg), newTestRP(t, cfg)
	loc, ck := login(t, a, "/login")
	code := f.issueCode(loc, "")
	if _, _, err, _ := callback(b, ck, loc.Query().Get("state"), code); err != nil {
		t.Fatal(err)
	}
	// A different secret must reject the cookie.
	cfg.CookieSecret = []byte("another-secret-another-secret-xx")
	c := newTestRP(t, cfg)
	loc, ck = login(t, a, "/login")
	code = f.issueCode(loc, "")
	if _, _, err, _ := callback(c, ck, loc.Query().Get("state"), code); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestStateFailures(t *testing.T) {
	f := newFakeProvider(t, "")
	rp := newTestRP(t, testConfig(f))
	loc, ck := login(t, rp, "/login")
	state := loc.Query().Get("state")
	code := f.issueCode(loc, "")

	if _, _, err, _ := callback(rp, nil, state, code); !errors.Is(err, ErrStateMissing) {
		t.Errorf("missing cookie: %v", err)
	}
	tampered := *ck
	i := strings.LastIndex(tampered.Value, ".")
	last := tampered.Value[len(tampered.Value)-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	tampered.Value = tampered.Value[:len(tampered.Value)-1] + string(repl)
	_ = i
	if _, _, err, _ := callback(rp, &tampered, state, code); !errors.Is(err, ErrStateInvalid) {
		t.Errorf("tampered: %v", err)
	}
	// Tampered payload (re-using the old signature).
	p, sig, _ := strings.Cut(ck.Value, ".")
	swapped := &http.Cookie{Name: ck.Name, Value: p[:len(p)-1] + "A" + "." + sig}
	if p[len(p)-1] == 'A' {
		swapped.Value = p[:len(p)-1] + "B" + "." + sig
	}
	if _, _, err, _ := callback(rp, swapped, state, code); !errors.Is(err, ErrStateInvalid) {
		t.Errorf("payload tampered: %v", err)
	}
	expired := &http.Cookie{Name: ck.Name, Value: rp.seal(loginState{State: state, Nonce: "n", Verifier: "v", Expires: time.Now().Add(-time.Minute).Unix()})}
	if _, _, err, _ := callback(rp, expired, state, code); !errors.Is(err, ErrStateExpired) {
		t.Errorf("expired: %v", err)
	}
	if _, _, err, _ := callback(rp, ck, "other-state", code); !errors.Is(err, ErrStateMismatch) {
		t.Errorf("mismatch: %v", err)
	}
	if _, _, err, _ := callback(rp, ck, "", ""); !errors.Is(err, ErrCodeMissing) {
		t.Errorf("no code: %v", err)
	}
}

func TestNonceMismatch(t *testing.T) {
	f := newFakeProvider(t, "")
	f.nonceOverride = "attacker-nonce"
	rp := newTestRP(t, testConfig(f))
	if _, _, err := flow(t, f, rp, "/login"); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestPKCEMismatchRejected(t *testing.T) {
	f := newFakeProvider(t, "")
	rp := newTestRP(t, testConfig(f))
	loc, ck := login(t, rp, "/login")
	code := f.issueCode(loc, "bogus-challenge")
	_, _, err, _ := callback(rp, ck, loc.Query().Get("state"), code)
	if !errors.Is(err, ErrExchangeFailed) || !strings.Contains(err.Error(), "pkce") {
		t.Fatalf("err = %v", err)
	}
}

func TestNextSanitising(t *testing.T) {
	f := newFakeProvider(t, "")
	rp := newTestRP(t, testConfig(f))
	cases := map[string]string{
		"//evil":              "",
		"https://evil":        "",
		"/\\evil":             "",
		"/\\/evil":            "",
		"evil":                "",
		"/ok\\x":              "",
		"/a\nb":               "",
		"/templates":          "/templates",
		"/templates?x=1#frag": "/templates?x=1#frag",
		"javascript:alert(1)": "",
		"/%2F/evil":           "/%2F/evil", // still a relative path, not "//"
	}
	for in, want := range cases {
		id, next, err := flow(t, f, rp, "/login?next="+url.QueryEscape(in))
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		_ = id
		if next != want {
			t.Errorf("next %q -> %q, want %q", in, next, want)
		}
	}
}

func TestProviderErrorParam(t *testing.T) {
	f := newFakeProvider(t, "")
	rp := newTestRP(t, testConfig(f))
	r := httptest.NewRequest("GET", "/cb?error=access_denied&error_description=nope", nil)
	_, _, err := rp.Callback(httptest.NewRecorder(), r)
	if !errors.Is(err, ErrProviderError) || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("err = %v", err)
	}
}

func TestCustomClaimMap(t *testing.T) {
	f := newFakeProvider(t, "")
	f.claims = map[string]any{
		"groups":   []string{"Staff", "SuperAdmins"},
		"products": "calco",
		"admin":    true,
	}
	cfg := testConfig(f)
	cfg.Claims = ClaimMap{RolesClaim: "groups", AdminRole: "superadmins", EntitlementsClaim: "products", AdminBoolClaim: "nope"}
	rp := newTestRP(t, cfg)
	id, _, err := flow(t, f, rp, "/login")
	if err != nil {
		t.Fatal(err)
	}
	if !id.IsAdmin || !id.HasRole("staff") || !id.HasEntitlement("calco") || id.HasEntitlement("x") {
		t.Errorf("identity %+v", id)
	}
}

func TestAdminDerivation(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		admin  bool
	}{
		{"bool", map[string]any{"is_admin": true}, true},
		{"bool false", map[string]any{"is_admin": false}, false},
		{"roles array", map[string]any{"roles": []string{"x", "admin"}}, true},
		{"roles string", map[string]any{"roles": "admin"}, true},
		{"role string", map[string]any{"role": "admin"}, true},
		{"case-insensitive", map[string]any{"role": "ADMIN"}, true},
		{"other role", map[string]any{"role": "viewer", "roles": []string{"editor"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeProvider(t, "")
			f.claims = c.claims
			rp := newTestRP(t, testConfig(f))
			id, _, err := flow(t, f, rp, "/login")
			if err != nil {
				t.Fatal(err)
			}
			if id.IsAdmin != c.admin {
				t.Errorf("IsAdmin = %v", id.IsAdmin)
			}
		})
	}
}

func TestDiscoveryHostRewrite(t *testing.T) {
	// The public issuer host does not resolve; only the rewrite can reach the fake.
	f := newFakeProvider(t, "http://idp.public.invalid:4444")
	rp := newTestRP(t, testConfig(f))
	id, _, err := flow(t, f, rp, "/login")
	if err != nil {
		t.Fatal(err)
	}
	if id.Issuer != "http://idp.public.invalid:4444" || f.hits < 3 {
		t.Errorf("issuer %q hits %d", id.Issuer, f.hits)
	}
}

func TestLazyDiscoveryRetries(t *testing.T) {
	f := newFakeProvider(t, "")
	cfg := testConfig(f)
	cfg.DiscoveryURL = ""
	cfg.IssuerURL = "http://127.0.0.1:1" // nothing listens
	rp := newTestRP(t, cfg)
	w := httptest.NewRecorder()
	rp.LoginHandler().ServeHTTP(w, httptest.NewRequest("GET", "/login", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", w.Code)
	}
	// Provider comes up: point at the working issuer; error must not be cached.
	rp.disc.issuer = f.issuer
	w = httptest.NewRecorder()
	rp.LoginHandler().ServeHTTP(w, httptest.NewRequest("GET", "/login", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("retry code %d", w.Code)
	}
}

func TestEndSessionURL(t *testing.T) {
	f := newFakeProvider(t, "")
	rp := newTestRP(t, testConfig(f))
	u, ok := rp.EndSessionURL("idtok", "https://app.example/")
	if !ok {
		t.Fatal("no end session url")
	}
	pu, _ := url.Parse(u)
	if pu.Path != "/logout" || pu.Query().Get("id_token_hint") != "idtok" || pu.Query().Get("post_logout_redirect_uri") != "https://app.example/" {
		t.Errorf("url %s", u)
	}
}

func TestCallbackHandler(t *testing.T) {
	f := newFakeProvider(t, "")
	rp := newTestRP(t, testConfig(f))
	var got Identity
	h := rp.CallbackHandler(func(w http.ResponseWriter, r *http.Request, id Identity, next string) error {
		got = id
		http.Redirect(w, r, "/", http.StatusFound)
		return nil
	}, func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, err.Error(), http.StatusUnauthorized)
	})
	loc, ck := login(t, rp, "/login")
	code := f.issueCode(loc, "")
	r := httptest.NewRequest("GET", "/cb?state="+loc.Query().Get("state")+"&code="+code, nil)
	r.AddCookie(ck)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusFound || got.Subject != "user-1" {
		t.Fatalf("code %d id %+v", w.Code, got)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/cb?error=x", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("error code %d", w.Code)
	}
}

func TestConfig(t *testing.T) {
	base := Config{IssuerURL: "https://i", ClientID: "c", RedirectURL: "https://a/cb", CookieSecret: testSecretBytes}
	for name, mut := range map[string]func(*Config){
		"issuer":   func(c *Config) { c.IssuerURL = "" },
		"client":   func(c *Config) { c.ClientID = "" },
		"secret":   func(c *Config) { c.CookieSecret = nil },
		"redirect": func(c *Config) { c.RedirectURL = "" },
	} {
		c := base
		mut(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	c := base
	c.Scopes = []string{"email", "openid", "groups"}
	rp, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rp.cfg.Scopes, " ") != "openid email groups" {
		t.Errorf("scopes %v", rp.cfg.Scopes)
	}
	c.RedirectURL = ""
	c.RedirectURLFunc = func(r *http.Request) string { return "https://" + r.Host + "/cb" }
	if _, err := New(c); err != nil {
		t.Error(err)
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("X_ISSUER_URL", "https://id.example")
	t.Setenv("X_DISCOVERY_URL", "http://hydra:4444")
	t.Setenv("X_CLIENT_ID", "cid")
	t.Setenv("X_CLIENT_SECRET", "sec")
	t.Setenv("X_REDIRECT_URL", "https://a/cb")
	t.Setenv("X_SCOPES", "openid groups")
	t.Setenv("X_ADMIN_CLAIM", "adm")
	t.Setenv("X_ROLES_CLAIM", "groups")
	t.Setenv("X_ROLE_CLAIM", "r")
	t.Setenv("X_ADMIN_ROLE", "root")
	t.Setenv("X_ENTITLEMENTS_CLAIM", "apps")
	c := ConfigFromEnv("X_")
	want := ClaimMap{AdminBoolClaim: "adm", RolesClaim: "groups", RoleClaim: "r", AdminRole: "root", EntitlementsClaim: "apps", EmailClaim: "email", NameClaim: "name"}
	if c.IssuerURL != "https://id.example" || c.DiscoveryURL != "http://hydra:4444" || c.ClientID != "cid" ||
		c.ClientSecret != "sec" || c.RedirectURL != "https://a/cb" || len(c.Scopes) != 2 || c.Claims != want {
		t.Errorf("%+v", c)
	}
	if d := ConfigFromEnv("NOPE_"); d.Claims != DefaultClaimMap() {
		t.Errorf("defaults %+v", d.Claims)
	}
}

func TestHelpers(t *testing.T) {
	if WWWAuthenticate("") != "Bearer" {
		t.Error("bare")
	}
	if got := WWWAuthenticate("https://a/.well-known/oauth-protected-resource"); got != `Bearer resource_metadata="https://a/.well-known/oauth-protected-resource"` {
		t.Error(got)
	}
	m := ProtectedResourceMetadata("https://a/mcp", []string{"https://id"}, []string{"openid"})
	if m["resource"] != "https://a/mcp" || m["bearer_methods_supported"].([]string)[0] != "header" {
		t.Errorf("%v", m)
	}
}
