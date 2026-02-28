package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewObservability(t *testing.T) {
	obs := NewObservability(nil, nil)
	assert.NotNil(t, obs)
	assert.Nil(t, obs.Logs())
	assert.Nil(t, obs.Metrics())

	// Test logging methods with nil logs - should not panic
	obs.Info("test")
	obs.Warn("test")
	obs.Debug("test")
	obs.Error("test")
	obs.Panic("test")
}
