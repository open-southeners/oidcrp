# oidcrp

A small, provider-agnostic OpenID Connect **relying party** for Go (`net/http` only, router-agnostic).
Works with Unikia ID (Ory Hydra/Kratos), any other Ory deployment, Keycloak, and any standards-compliant OP.

- Authorization-code login with **PKCE (S256)**
- **Stateless** login state: signed, httpOnly cookie (no server-side store, safe with multiple instances)
- Configurable **claim mapping** (admin, roles, entitlements, email, name)
- **Resource-server** token validation: JWT via JWKS or RFC 7662 introspection, exact audience check
- Lazy provider discovery that retries after failures; optional internal discovery host

## Install

```sh
go get github.com/open-southeners/oidcrp
```

## Login

```go
cfg := oidcrp.ConfigFromEnv("OIDC_")
cfg.CookieSecret = []byte(os.Getenv("SESSION_SECRET")) // 32+ random bytes, shared by all instances
cfg.Secure = true                                       // HTTPS deployments
rp, err := oidcrp.New(cfg)

mux.Handle("/auth/oidc/login", rp.LoginHandler()) // optional ?next=/path (same-origin paths only)
mux.Handle("/auth/oidc/callback", rp.CallbackHandler(
    func(w http.ResponseWriter, r *http.Request, id oidcrp.Identity, returnTo string) error {
        // create your session from id.Subject / id.Email / id.IsAdmin ...
        http.Redirect(w, r, cmp.Or(returnTo, "/"), http.StatusFound)
        return nil
    },
    func(w http.ResponseWriter, r *http.Request, err error) {
        // map errors.Is(err, oidcrp.ErrStateMismatch) etc. to HTTP codes
        http.Error(w, "login failed", http.StatusUnauthorized)
    },
))
```

Use `rp.Callback(w, r)` directly if you prefer to handle the result yourself, and
`rp.EndSessionURL(idTokenHint, postLogoutRedirectURI)` for RP-initiated logout.
With gin: `r.GET("/auth/oidc/login", gin.WrapH(rp.LoginHandler()))`.

Errors from `Callback` wrap: `ErrProviderError`, `ErrCodeMissing`, `ErrStateMissing`, `ErrStateInvalid`,
`ErrStateExpired`, `ErrStateMismatch`, `ErrExchangeFailed`, `ErrIDTokenMissing`, `ErrIDTokenInvalid`,
`ErrNonceMismatch`, `ErrDiscovery`.

## Token validation (resource server)

```go
v, err := oidcrp.NewTokenValidator(oidcrp.TokenConfig{
    IssuerURL:                 "https://id.example.com",
    Audience:                  "https://api.example.com/mcp", // required, matched exactly
    IntrospectionURL:          "https://hydra-admin/admin/oauth2/introspect", // opaque tokens only
    IntrospectionClientID:     "rs", IntrospectionClientSecret: "secret",
})
info, err := v.Validate(ctx, bearerToken) // info.Identity, info.Audiences, info.Scopes

w.Header().Set("WWW-Authenticate", oidcrp.WWWAuthenticate("https://api.example.com/.well-known/oauth-protected-resource"))
meta := oidcrp.ProtectedResourceMetadata("https://api.example.com/mcp", []string{"https://id.example.com"}, []string{"openid"})
```

Three-segment tokens are verified as JWTs and the result is final (a bad JWT never falls back to introspection).
Other tokens are introspected (non-200 rejected, `active` required). `sub` is required; `aud` may be a string or array.

## ConfigFromEnv

`ConfigFromEnv("OIDC_")` reads:

| Variable | Meaning |
|---|---|
| `OIDC_ISSUER_URL` | Public issuer URL |
| `OIDC_DISCOVERY_URL` | Optional internal URL; only host[:port] replaces the issuer's for server-side calls |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | Client credentials |
| `OIDC_REDIRECT_URL` | Callback URL (or set `RedirectURLFunc`) |
| `OIDC_SCOPES` | Space separated; `openid` is forced first (default `openid email profile`) |
| `OIDC_ADMIN_CLAIM` | Boolean admin claim (default `is_admin`) |
| `OIDC_ROLES_CLAIM` / `OIDC_ROLE_CLAIM` | Roles claim (array or string, default `roles`) / single role (default `role`) |
| `OIDC_ADMIN_ROLE` | Role name granting admin, case-insensitive (default `admin`) |
| `OIDC_ENTITLEMENTS_CLAIM` | Entitlements claim (default `authorized_apps`) |

`CookieSecret`, `Secure`, `CookieName`, `StateTTL`, `HTTPClient` are set in code.

## Example configs

```sh
# Unikia ID (defaults already match its claims)
OIDC_ISSUER_URL=https://id.unikia.es
OIDC_DISCOVERY_URL=http://hydra:4444   # optional internal route

# Any Ory Hydra
OIDC_ISSUER_URL=https://auth.other-company.com
OIDC_ROLES_CLAIM=roles

# Keycloak
OIDC_ISSUER_URL=https://kc.example.com/realms/main
OIDC_ROLES_CLAIM=groups
OIDC_ADMIN_ROLE=realm-admin
OIDC_ENTITLEMENTS_CLAIM=products
```

## Claim mapping

| Identity field | Source (default claim) |
|---|---|
| `Issuer`, `Subject` | `iss`, `sub` |
| `Email`, `Name` | `email`, `name` (`EmailClaim`, `NameClaim`); introspection falls back to `username` for email |
| `EmailVerified` | `email_verified` |
| `Roles` | `roles` plus `role` (string or array) |
| `IsAdmin` | `is_admin` is true, or any role equals `AdminRole` (case-insensitive) |
| `Entitlements` | `authorized_apps` (string or array) |
| `Raw` | all claims |

## Security notes

- State, nonce and PKCE verifier live in an HMAC-SHA256 signed, httpOnly, SameSite=Lax cookie
  (`Secure` when configured, expires after `StateTTL`), binding the login to the browser (prevents login CSRF).
  The cookie is cleared on every callback, and signature/state/nonce are compared in constant time.
- PKCE S256 is always used; the ID token is verified (signature, issuer, expiry, client ID) and its nonce checked.
- `next` is only honoured for same-origin relative paths (rejects `//`, `/\`, schemes, control characters).
- Token validation enforces an exact audience match (RFC 8707); JWT failures never fall back to introspection.
- Use a 32+ byte random `CookieSecret`; rotating it invalidates in-flight logins only.

## License

MIT
