package oidcrp

import (
	"crypto/subtle"
	"fmt"
)

func constEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ProtectedResourceMetadata returns the RFC 9728 document body for
// /.well-known/oauth-protected-resource.
func ProtectedResourceMetadata(resource string, authServers, scopes []string) map[string]any {
	return map[string]any{
		"resource":                 resource,
		"authorization_servers":    authServers,
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         scopes,
	}
}

// WWWAuthenticate returns the WWW-Authenticate challenge value for a 401.
func WWWAuthenticate(resourceMetadataURL string) string {
	if resourceMetadataURL == "" {
		return "Bearer"
	}
	return fmt.Sprintf(`Bearer resource_metadata="%s"`, resourceMetadataURL)
}
