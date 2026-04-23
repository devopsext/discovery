package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURL_ParseURL(t *testing.T) {
	tests := []struct {
		name      string
		s         string
		defSchema string
		expected  string
		user      string
		pass      string
	}{
		{
			name:      "Full URL",
			s:         "https://user:pass@example.com/path", // #nosec G101
			defSchema: "http",
			expected:  "https://user:pass@example.com/path", // #nosec G101
			user:      "user",
			pass:      "pass",
		},
		{
			name:      "No schema",
			s:         "example.com/path",
			defSchema: "https",
			expected:  "https://example.com/path",
		},
		{
			name:      "User only",
			s:         "user@example.com",
			defSchema: "http",
			expected:  "http://user:@example.com",
			user:      "user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := ParseURL(tt.s, tt.defSchema)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, u.String())
			if tt.user != "" {
				assert.Equal(t, tt.user, u.User.Username())
				if tt.pass != "" {
					p, _ := u.User.Password()
					assert.Equal(t, tt.pass, p)
				}
			}
		})
	}
}

func TestURL_ParseNames(t *testing.T) {
	names := "prom=http://prom.svc:9090, vic=https://user:pass@vic.svc, plain.svc"
	urls := ParseNames(names, nil)

	assert.Len(t, urls, 3)

	assert.Equal(t, "prom", urls[0].Name)
	assert.Equal(t, "http://prom.svc:9090", urls[0].URL)

	assert.Equal(t, "vic", urls[1].Name)
	assert.Equal(t, "https://vic.svc", urls[1].URL)
	assert.Equal(t, "user", urls[1].User)
	assert.Equal(t, "pass", urls[1].Password)

	assert.Equal(t, "unknown2", urls[2].Name)
	assert.Equal(t, "http://plain.svc", urls[2].URL)
}
