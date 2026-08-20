package services

import "testing"

func TestApprovedRedirectMatches(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		approved string
		want     bool
	}{
		{
			name:     "exact",
			uri:      "https://app.example.com/callback",
			approved: "https://app.example.com/callback",
			want:     true,
		},
		{
			name:     "chatgpt connector id",
			uri:      "https://chatgpt.com/connector/oauth/7GEMN67TZ5Pb",
			approved: "https://chatgpt.com/connector/oauth/*",
			want:     true,
		},
		{
			name:     "nested path",
			uri:      "https://chatgpt.com/connector/oauth/a/b",
			approved: "https://chatgpt.com/connector/oauth/*",
			want:     false,
		},
		{
			name:     "query is not covered",
			uri:      "https://chatgpt.com/connector/oauth/id?next=evil",
			approved: "https://chatgpt.com/connector/oauth/*",
			want:     false,
		},
		{
			name:     "host mismatch",
			uri:      "https://evil.example.com/connector/oauth/id",
			approved: "https://chatgpt.com/connector/oauth/*",
			want:     false,
		},
		{
			name:     "wildcard is not implicit",
			uri:      "https://app.example.com/other",
			approved: "https://app.example.com/callback",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := approvedRedirectMatches(tt.uri, tt.approved); got != tt.want {
				t.Fatalf("approvedRedirectMatches(%q, %q) = %v, want %v", tt.uri, tt.approved, got, tt.want)
			}
		})
	}
}
