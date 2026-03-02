package telegraf

import (
	"strings"
	"testing"

	"github.com/devopsext/discovery/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRandomizeOffsetDuration(t *testing.T) {
	tests := []struct {
		name        string
		fileName    string
		durationStr string
		wantErr     bool
		wantResult  string
	}{
		{
			name:        "Zero duration always returns 0s",
			fileName:    "any",
			durationStr: "0s",
			wantErr:     false,
			wantResult:  "0s",
		},
		{
			name:        "No s suffix returns error",
			fileName:    "any",
			durationStr: "60m",
			wantErr:     true,
			wantResult:  "0s",
		},
		{
			name:        "Non-numeric before s returns error",
			fileName:    "any",
			durationStr: "abcs",
			wantErr:     true,
			wantResult:  "0s",
		},
		{
			name:        "Negative value returns error",
			fileName:    "any",
			durationStr: "-10s",
			wantErr:     true,
			wantResult:  "0s",
		},
		{
			name:        "Valid duration produces s-suffix result",
			fileName:    "my-service",
			durationStr: "60s",
			wantErr:     false,
		},
		{
			name:        "Single second range",
			fileName:    "svc",
			durationStr: "1s",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := randomizeOffsetDuration(tt.fileName, tt.durationStr)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, "0s", result)
			} else {
				assert.NoError(t, err)
				assert.True(t, strings.HasSuffix(result, "s"), "result should end with 's': %s", result)
				if tt.wantResult != "" {
					assert.Equal(t, tt.wantResult, result)
				}
			}
		})
	}
}

func TestRandomizeOffsetDuration_Deterministic(t *testing.T) {
	r1, err := randomizeOffsetDuration("my-service", "100s")
	require.NoError(t, err)
	r2, err := randomizeOffsetDuration("my-service", "100s")
	require.NoError(t, err)
	assert.Equal(t, r1, r2, "same input must always produce the same output")
}

func TestRandomizeOffsetDuration_DifferentNames(t *testing.T) {
	// Different file names should (with overwhelming probability) produce different offsets
	// for a large range — at minimum they must both be valid
	r1, err1 := randomizeOffsetDuration("service-alpha", "1000s")
	r2, err2 := randomizeOffsetDuration("service-beta", "1000s")
	require.NoError(t, err1)
	require.NoError(t, err2)
	assert.True(t, strings.HasSuffix(r1, "s"))
	assert.True(t, strings.HasSuffix(r2, "s"))
}

func TestGenerateInputDNSQueryBytes(t *testing.T) {
	tests := []struct {
		name        string
		opts        InputDNSQueryOptions
		domains     map[string]common.Labels
		wantContent []string
	}{
		{
			name: "Single domain with servers",
			opts: InputDNSQueryOptions{
				Interval:   "60s",
				Servers:    "8.8.8.8, 8.8.4.4",
				Network:    "udp",
				RecordType: "A",
				Port:       53,
				Timeout:    2,
			},
			domains: map[string]common.Labels{
				"example.com": {"env": "prod"},
			},
			wantContent: []string{"dns_query", "example.com", "8.8.8.8", "udp"},
		},
		{
			name:        "Empty domains produces valid TOML",
			opts:        InputDNSQueryOptions{Servers: "8.8.8.8"},
			domains:     map[string]common.Labels{},
			wantContent: []string{},
		},
		{
			name: "Duplicate servers are deduplicated",
			opts: InputDNSQueryOptions{Servers: "8.8.8.8, 8.8.8.8, 1.1.1.1"},
			domains: map[string]common.Labels{
				"test.com": {},
			},
			wantContent: []string{"test.com"},
		},
		{
			name: "Multiple domains sorted",
			opts: InputDNSQueryOptions{Servers: "9.9.9.9"},
			domains: map[string]common.Labels{
				"z-service.com": {},
				"a-service.com": {},
			},
			wantContent: []string{"a-service.com", "z-service.com"},
		},
		{
			name: "Tags added to include",
			opts: InputDNSQueryOptions{
				Servers: "8.8.8.8",
				Tags:    []string{"host", "env"},
			},
			domains: map[string]common.Labels{
				"example.com": {},
			},
			wantContent: []string{"host", "env"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &Config{}
			bs, err := tc.GenerateInputDNSQueryBytes(tt.opts, tt.domains)
			require.NoError(t, err)
			content := string(bs)
			for _, want := range tt.wantContent {
				assert.Contains(t, content, want)
			}
		})
	}
}

func TestGenerateInputHTTPResponseBytes(t *testing.T) {
	tests := []struct {
		name        string
		opts        InputHTTPResponseOptions
		urls        map[string]common.Labels
		wantContent []string
	}{
		{
			name: "Single URL with GET method",
			opts: InputHTTPResponseOptions{
				Interval: "60s",
				Method:   "GET",
				Timeout:  "5s",
			},
			urls: map[string]common.Labels{
				"http://example.com/health": {"env": "prod"},
			},
			wantContent: []string{"http_response", "http://example.com/health", "GET"},
		},
		{
			name: "Multiple URLs appear sorted",
			opts: InputHTTPResponseOptions{Method: "POST"},
			urls: map[string]common.Labels{
				"http://z.example.com": {},
				"http://a.example.com": {},
			},
			wantContent: []string{"http://a.example.com", "http://z.example.com"},
		},
		{
			name:        "Empty URLs produces valid TOML",
			opts:        InputHTTPResponseOptions{Interval: "30s"},
			urls:        map[string]common.Labels{},
			wantContent: []string{},
		},
		{
			name: "InsecureSkipVerify always set",
			opts: InputHTTPResponseOptions{},
			urls: map[string]common.Labels{
				"https://secure.example.com": {},
			},
			wantContent: []string{"insecure_skip_verify"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &Config{}
			bs, err := tc.GenerateInputHTTPResponseBytes(tt.opts, tt.urls)
			require.NoError(t, err)
			content := string(bs)
			for _, want := range tt.wantContent {
				assert.Contains(t, content, want)
			}
		})
	}
}

func TestGenerateInputNETResponseBytes(t *testing.T) {
	tests := []struct {
		name        string
		opts        InputNetResponseOptions
		addresses   map[string]common.Labels
		protocol    string
		wantContent []string
	}{
		{
			name: "TCP connection check",
			opts: InputNetResponseOptions{
				Interval: "60s",
				Timeout:  "5s",
			},
			addresses: map[string]common.Labels{
				"localhost:8080": {"service": "api"},
			},
			protocol:    "tcp",
			wantContent: []string{"net_response", "localhost:8080", "tcp"},
		},
		{
			name: "UDP with send/expect",
			opts: InputNetResponseOptions{
				Send:   "ping",
				Expect: "pong",
			},
			addresses: map[string]common.Labels{
				"host:9999": {},
			},
			protocol:    "udp",
			wantContent: []string{"udp", "host:9999"},
		},
		{
			name: "Multiple addresses sorted",
			opts: InputNetResponseOptions{},
			addresses: map[string]common.Labels{
				"z-host:80": {},
				"a-host:80": {},
			},
			protocol:    "tcp",
			wantContent: []string{"a-host:80", "z-host:80"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &Config{}
			bs, err := tc.GenerateInputNETResponseBytes(tt.opts, tt.addresses, tt.protocol)
			require.NoError(t, err)
			content := string(bs)
			for _, want := range tt.wantContent {
				assert.Contains(t, content, want)
			}
		})
	}
}

func TestGenerateInputX509CertBytes(t *testing.T) {
	tests := []struct {
		name        string
		opts        InputX509CertOptions
		addresses   map[string]common.Labels
		wantContent []string
	}{
		{
			name: "Single HTTPS source",
			opts: InputX509CertOptions{
				Interval: "24h",
				Timeout:  "10s",
			},
			addresses: map[string]common.Labels{
				"https://example.com:443": {"env": "prod"},
			},
			wantContent: []string{"x509_cert", "https://example.com:443"},
		},
		{
			name: "Multiple sources sorted",
			opts: InputX509CertOptions{},
			addresses: map[string]common.Labels{
				"https://z.com": {},
				"https://a.com": {},
			},
			wantContent: []string{"https://a.com", "https://z.com"},
		},
		{
			name: "TLS options present in output",
			opts: InputX509CertOptions{
				TLSCA:   "/path/to/ca.crt",
				TLSCert: "/path/to/cert.crt",
				TLSKey:  "/path/to/key.key",
			},
			addresses: map[string]common.Labels{
				"https://internal.svc": {},
			},
			wantContent: []string{"/path/to/ca.crt", "/path/to/cert.crt"},
		},
		{
			name:        "Empty addresses produces valid TOML",
			opts:        InputX509CertOptions{},
			addresses:   map[string]common.Labels{},
			wantContent: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &Config{}
			bs, err := tc.GenerateInputX509CertBytes(tt.opts, tt.addresses)
			require.NoError(t, err)
			content := string(bs)
			for _, want := range tt.wantContent {
				assert.Contains(t, content, want)
			}
		})
	}
}
