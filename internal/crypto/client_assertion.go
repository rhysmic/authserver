package crypto

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	clientAssertionClockSkew = 30 * time.Second
	clientAssertionMaxAge    = 5 * time.Minute
)

// ClientAssertionClaims are the claims required by RFC 7523 private_key_jwt
// client authentication. The issuer and subject are both the client_id.
type ClientAssertionClaims struct {
	Issuer   string       `json:"iss"`
	Subject  string       `json:"sub"`
	Audience jwt.Audience `json:"aud"`
	Expiry   int64        `json:"exp"`
	IssuedAt int64        `json:"iat"`
	JTI      string       `json:"jti"`
}

// ValidateClientAssertion verifies a private_key_jwt assertion against the
// client's registered JWKS and validates its RFC 7523 claims. The caller is
// responsible for consuming JTI so replay prevention can use the configured
// persistence adapter.
func ValidateClientAssertion(
	raw string,
	trustedKeys *jose.JSONWebKeySet,
	expectedClientID string,
	expectedAudience string,
	expectedAlgorithm string,
	now time.Time,
) (*ClientAssertionClaims, error) {
	if strings.TrimSpace(raw) == "" || trustedKeys == nil || len(trustedKeys.Keys) == 0 {
		return nil, fmt.Errorf("client assertion is empty or has no trusted keys")
	}

	algorithm, ok := clientAssertionAlgorithm(expectedAlgorithm)
	if !ok {
		return nil, fmt.Errorf("unsupported client assertion signing algorithm")
	}
	parsed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{algorithm})
	if err != nil || len(parsed.Signatures) != 1 {
		return nil, fmt.Errorf("invalid client assertion signature")
	}
	header := parsed.Signatures[0].Header
	if header.Algorithm != string(algorithm) {
		return nil, fmt.Errorf("unexpected client assertion signing algorithm")
	}

	keys := trustedKeys.Keys
	if header.KeyID != "" {
		keys = trustedKeys.Key(header.KeyID)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("client assertion signing key not found")
	}

	var payload []byte
	for i := range keys {
		payload, err = parsed.Verify(keys[i].Key)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("client assertion signature verification failed")
	}

	var claims ClientAssertionClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("invalid client assertion claims")
	}
	if claims.Issuer == "" || claims.Issuer != expectedClientID {
		return nil, fmt.Errorf("client assertion issuer mismatch")
	}
	if claims.Subject == "" || claims.Subject != expectedClientID {
		return nil, fmt.Errorf("client assertion subject mismatch")
	}
	if len(claims.Audience) == 0 || !claims.Audience.Contains(expectedAudience) {
		return nil, fmt.Errorf("client assertion audience mismatch")
	}
	if claims.Expiry == 0 || claims.IssuedAt == 0 || claims.JTI == "" {
		return nil, fmt.Errorf("client assertion missing required claim")
	}

	nowUnix := now.Unix()
	if nowUnix > claims.Expiry+int64(clientAssertionClockSkew/time.Second) {
		return nil, fmt.Errorf("client assertion expired")
	}
	if claims.IssuedAt > nowUnix+int64(clientAssertionClockSkew/time.Second) {
		return nil, fmt.Errorf("client assertion issued in the future")
	}
	if claims.IssuedAt < nowUnix-int64(clientAssertionMaxAge/time.Second)-int64(clientAssertionClockSkew/time.Second) {
		return nil, fmt.Errorf("client assertion is too old")
	}
	if claims.Expiry < claims.IssuedAt {
		return nil, fmt.Errorf("client assertion expiry precedes issued-at")
	}
	if claims.Expiry-claims.IssuedAt > int64(clientAssertionMaxAge/time.Second)+int64(clientAssertionClockSkew/time.Second) {
		return nil, fmt.Errorf("client assertion lifetime is too long")
	}
	return &claims, nil
}

func clientAssertionAlgorithm(name string) (jose.SignatureAlgorithm, bool) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "RS256":
		return jose.RS256, true
	case "RS384":
		return jose.RS384, true
	case "RS512":
		return jose.RS512, true
	case "PS256":
		return jose.PS256, true
	case "PS384":
		return jose.PS384, true
	case "PS512":
		return jose.PS512, true
	case "ES256":
		return jose.ES256, true
	case "ES384":
		return jose.ES384, true
	case "ES512":
		return jose.ES512, true
	default:
		return "", false
	}
}
