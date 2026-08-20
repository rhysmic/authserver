package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/authplane/authserver/internal/crypto"
	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/domain/client"
	"github.com/authplane/authserver/internal/ports/output"
	"github.com/authplane/authserver/internal/ssrf"
)

const (
	clientAssertionJWKSCacheTTL = 5 * time.Minute
	clientAssertionHTTPTimeout  = 10 * time.Second
	clientAssertionMaxJWKSBody  = 512 * 1024
)

type clientAssertionJWKSCacheEntry struct {
	keys      *jose.JSONWebKeySet
	expiresAt time.Time
}

// ClientAssertionVerifier authenticates OAuth clients using RFC 7523
// private_key_jwt assertions. JWKS documents are cached in memory and are
// refreshed on expiry or a signing-key (kid) miss. Assertion JTIs are
// consumed through the configured store to prevent replay.
type ClientAssertionVerifier struct {
	mu         sync.RWMutex
	cache      map[string]clientAssertionJWKSCacheEntry
	jtiStore   output.AssertionJTIStore
	httpClient *http.Client
	now        func() time.Time
}

// NewClientAssertionVerifier creates a production verifier with SSRF-safe
// HTTPS JWKS fetching and SQLite/Postgres-backed replay protection.
func NewClientAssertionVerifier(jtiStore output.AssertionJTIStore) *ClientAssertionVerifier {
	return &ClientAssertionVerifier{
		cache:    make(map[string]clientAssertionJWKSCacheEntry),
		jtiStore: jtiStore,
		httpClient: &http.Client{
			Timeout:   clientAssertionHTTPTimeout,
			Transport: ssrf.NewSafeTransport(),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		now: time.Now,
	}
}

// Verify validates the assertion for the registered client and consumes its
// jti. All failures are returned as invalid_client so token endpoint errors do
// not disclose whether a key, claim, or replay check failed.
func (v *ClientAssertionVerifier) Verify(ctx context.Context, c *client.Client, raw, tokenEndpoint string) error {
	if c == nil || c.TokenEndpointAuthMethod != "private_key_jwt" || c.JWKSURI == "" || strings.TrimSpace(raw) == "" {
		return domain.ErrInvalidClient
	}
	if tokenEndpoint == "" {
		return domain.ErrInvalidClient
	}

	now := v.now()
	keys, err := v.getJWKS(ctx, c.JWKSURI, false)
	if err != nil {
		return domain.ErrInvalidClient
	}
	alg := c.TokenEndpointAuthSigningAlg
	if alg == "" {
		alg = "RS256"
	}
	claims, err := crypto.ValidateClientAssertion(raw, keys, c.ID, tokenEndpoint, alg, now)
	if err != nil {
		// A rotated key may arrive with a new kid before the cache expires.
		keys, refreshErr := v.getJWKS(ctx, c.JWKSURI, true)
		if refreshErr != nil {
			return domain.ErrInvalidClient
		}
		claims, err = crypto.ValidateClientAssertion(raw, keys, c.ID, tokenEndpoint, alg, now)
		if err != nil {
			return domain.ErrInvalidClient
		}
	}

	if v.jtiStore == nil {
		return domain.ErrInvalidClient
	}
	if err := v.jtiStore.ConsumeJTI(ctx, claims.JTI, time.Unix(claims.Expiry, 0).Add(30*time.Second)); err != nil {
		return domain.ErrInvalidClient
	}
	return nil
}

func (v *ClientAssertionVerifier) getJWKS(ctx context.Context, rawURI string, force bool) (*jose.JSONWebKeySet, error) {
	if err := validateJWKSURI(rawURI); err != nil {
		return nil, err
	}
	now := v.now()
	if !force {
		v.mu.RLock()
		entry, ok := v.cache[rawURI]
		v.mu.RUnlock()
		if ok && now.Before(entry.expiresAt) {
			return entry.keys, nil
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURI, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, clientAssertionMaxJWKSBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > clientAssertionMaxJWKSBody {
		return nil, fmt.Errorf("jwks response exceeds limit")
	}
	var keys jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keys); err != nil || len(keys.Keys) == 0 {
		return nil, fmt.Errorf("invalid jwks document")
	}
	v.mu.Lock()
	v.cache[rawURI] = clientAssertionJWKSCacheEntry{keys: &keys, expiresAt: now.Add(clientAssertionJWKSCacheTTL)}
	v.mu.Unlock()
	return &keys, nil
}

func validateJWKSURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("jwks_uri must be an https URL")
	}
	return nil
}
