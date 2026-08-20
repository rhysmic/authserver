package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestValidateClientAssertionValidRS256(t *testing.T) {
	key, public := clientAssertionTestKey(t, "chatgpt-1")
	now := time.Unix(1_700_000_000, 0)
	raw := signClientAssertion(t, key, map[string]any{
		"iss": "https://chatgpt.com/oauth/client.json",
		"sub": "https://chatgpt.com/oauth/client.json",
		"aud": "https://auth.example.com/oauth/token",
		"exp": now.Add(2 * time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": "assertion-1",
	})

	claims, err := ValidateClientAssertion(
		raw,
		&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}},
		"https://chatgpt.com/oauth/client.json",
		"https://auth.example.com/oauth/token",
		"RS256",
		now,
	)
	if err != nil {
		t.Fatalf("expected valid assertion, got %v", err)
	}
	if claims.JTI != "assertion-1" || !claims.Audience.Contains("https://auth.example.com/oauth/token") {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestValidateClientAssertionRejectsInvalidClaims(t *testing.T) {
	key, public := clientAssertionTestKey(t, "chatgpt-1")
	now := time.Unix(1_700_000_000, 0)
	base := map[string]any{
		"iss": "https://chatgpt.com/oauth/client.json",
		"sub": "https://chatgpt.com/oauth/client.json",
		"aud": "https://auth.example.com/oauth/token",
		"exp": now.Add(2 * time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": "assertion-1",
	}

	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "wrong issuer", mutate: func(c map[string]any) { c["iss"] = "other" }},
		{name: "wrong subject", mutate: func(c map[string]any) { c["sub"] = "other" }},
		{name: "wrong audience", mutate: func(c map[string]any) { c["aud"] = "other" }},
		{name: "expired", mutate: func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() }},
		{name: "missing jti", mutate: func(c map[string]any) { delete(c, "jti") }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := make(map[string]any, len(base))
			for k, v := range base {
				claims[k] = v
			}
			tc.mutate(claims)
			raw := signClientAssertion(t, key, claims)
			if _, err := ValidateClientAssertion(
				raw,
				&jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}},
				"https://chatgpt.com/oauth/client.json",
				"https://auth.example.com/oauth/token",
				"RS256",
				now,
			); err == nil {
				t.Fatal("expected assertion to be rejected")
			}
		})
	}
}

func clientAssertionTestKey(t *testing.T, kid string) (*rsa.PrivateKey, jose.JSONWebKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key, jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"}
}

func signClientAssertion(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "chatgpt-1"))
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize assertion: %v", err)
	}
	return raw
}
