package oidcrp

import (
	"context"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
)

// discovery lazily resolves the OIDC provider. Failures are never cached, so a
// provider that is down at boot is retried on the next call.
type discovery struct {
	issuer string
	mu     sync.Mutex
	prov   *oidc.Provider
}

func (d *discovery) provider(ctx context.Context) (*oidc.Provider, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.prov != nil {
		return d.prov, nil
	}
	p, err := oidc.NewProvider(ctx, d.issuer)
	if err != nil {
		return nil, err
	}
	d.prov = p
	return p, nil
}
