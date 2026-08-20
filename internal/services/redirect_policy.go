package services

import (
	"net/url"
	"strings"
)

// approvedRedirectMatches matches an approved redirect URI. Exact entries
// remain the default. A terminal /* path segment is supported for providers
// such as ChatGPT whose connector callback contains one generated ID segment.
// The wildcard never crosses a path separator and cannot be used in a host,
// scheme, query, or fragment.
func approvedRedirectMatches(uri, approved string) bool {
	if uri == approved {
		return true
	}
	if !strings.HasSuffix(approved, "/*") {
		return false
	}

	candidate, err := url.Parse(uri)
	if err != nil || candidate.Scheme == "" || candidate.Host == "" || candidate.User != nil {
		return false
	}
	pattern, err := url.Parse(approved)
	if err != nil || pattern.Scheme == "" || pattern.Host == "" || pattern.User != nil {
		return false
	}
	if !strings.EqualFold(candidate.Scheme, pattern.Scheme) || !strings.EqualFold(candidate.Host, pattern.Host) {
		return false
	}
	if pattern.RawQuery != "" || pattern.Fragment != "" || candidate.RawQuery != "" || candidate.Fragment != "" {
		return false
	}

	prefix := strings.TrimSuffix(pattern.Path, "*")
	if prefix == "" || !strings.HasSuffix(prefix, "/") || !strings.HasPrefix(candidate.Path, prefix) {
		return false
	}
	remainder := strings.TrimPrefix(candidate.Path, prefix)
	return remainder != "" && !strings.Contains(remainder, "/")
}
