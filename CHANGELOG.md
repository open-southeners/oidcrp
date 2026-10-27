# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-27

### Added

- `Identity.Tokens` carries the ID, access and refresh tokens (and access-token
  expiry) returned at login, so an app can pass the ID token as
  `id_token_hint` to `EndSessionURL` (required by Ory Hydra to honour
  `post_logout_redirect_uri`) or call APIs on the user's behalf. It is nil for
  identities from `TokenValidator`.

## [0.1.0] - 2026-10-27

### Added

- **OpenID Connect login** for any `net/http` router: authorization-code flow
  with PKCE (S256), ID-token signature/issuer/expiry/audience checks and nonce
  verification, through `LoginHandler`, `CallbackHandler` or `Callback`.
- **Stateless login state** kept in an HMAC-signed, httpOnly, SameSite=Lax
  cookie, so logins work across several instances without a shared store. Only
  same-origin relative `next` paths are honoured after login.
- **RP-initiated logout** URLs via `EndSessionURL`.
- **Claim mapping** into an `Identity` (subject, email, name, roles, admin flag,
  entitlements) with defaults matching Unikia ID and overrides for any other
  provider, such as Ory Hydra or Keycloak.
- **Resource-server token validation** with `NewTokenValidator`: JWTs checked
  against the provider's JWKS, opaque tokens through RFC 7662 introspection,
  and an exact audience match. Includes `WWWAuthenticate` and
  `ProtectedResourceMetadata` helpers for OAuth protected resources.
- `ConfigFromEnv` reads the configuration from prefixed environment variables
  (for example `OIDC_ISSUER_URL`), including an optional internal discovery
  host for server-to-server calls.
- Typed errors (`ErrStateMismatch`, `ErrExchangeFailed`, `ErrNonceMismatch` and
  others) for mapping login failures to HTTP responses.

[Unreleased]: https://github.com/open-southeners/oidcrp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/open-southeners/oidcrp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/open-southeners/oidcrp/releases/tag/v0.1.0
