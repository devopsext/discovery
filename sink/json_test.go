package sink

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/stretchr/testify/assert"
)

type mockDiscovery struct {
	name string
}

func (m *mockDiscovery) Discover()      {}
func (m *mockDiscovery) Name() string   { return m.name }
func (m *mockDiscovery) Source() string { return "mock" }

type mockSinkObject struct {
	m common.SinkMap
}

func (m *mockSinkObject) Map() common.SinkMap { return m.m }
func (m *mockSinkObject) Options() any        { return nil }

func TestJson_New(t *testing.T) {
	logger := sreCommon.NewLogs()
	obs := common.NewObservability(logger, nil)
	options := JsonOptions{
		Dir: t.TempDir(),
	}

	j := NewJson(options, obs)
	assert.NotNil(t, j)
	assert.Equal(t, "Json", j.Name())
}

func TestJson_New_EmptyDir(t *testing.T) {
	logger := sreCommon.NewLogs()
	obs := common.NewObservability(logger, nil)
	options := JsonOptions{
		Dir: "",
	}

	j := NewJson(options, obs)
	assert.Nil(t, j)
}

func TestJson_Process(t *testing.T) {
	logger := sreCommon.NewLogs()
	obs := common.NewObservability(logger, nil)
	dir := t.TempDir()
	options := JsonOptions{
		Dir: dir,
	}

	j := NewJson(options, obs)
	assert.NotNil(t, j)

	discovery := &mockDiscovery{name: "test-discovery"}
	sinkObject := &mockSinkObject{
		m: common.SinkMap{
			"key": "value",
		},
	}

	j.Process(discovery, sinkObject)

	filePath := filepath.Join(dir, "test-discovery.json")
	assert.FileExists(t, filePath)

	data, err := os.ReadFile(filePath)
	assert.NoError(t, err)
	assert.Contains(t, string(data), `"key":"value"`)
}
