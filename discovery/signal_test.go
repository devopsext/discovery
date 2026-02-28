package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignal_CheckDisabled(t *testing.T) {
	s := &Signal{}

	tests := []struct {
		name             string
		disabled         []string
		ident            string
		expectedDisabled bool
		expectedReason   string
	}{
		{
			name:             "Match exact",
			disabled:         []string{"host1", "host2"},
			ident:            "host1",
			expectedDisabled: true,
			expectedReason:   "host1",
		},
		{
			name:             "Match wildcard",
			disabled:         []string{"host*", "other"},
			ident:            "host123",
			expectedDisabled: true,
			expectedReason:   "host*",
		},
		{
			name:             "No match",
			disabled:         []string{"host1", "host2"},
			ident:            "host3",
			expectedDisabled: false,
			expectedReason:   "",
		},
		{
			name:             "Empty disabled list",
			disabled:         []string{},
			ident:            "host1",
			expectedDisabled: false,
			expectedReason:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			disabled, reason := s.checkDisabled(tt.disabled, tt.ident)
			assert.Equal(t, tt.expectedDisabled, disabled)
			assert.Equal(t, tt.expectedReason, reason)
		})
	}
}
