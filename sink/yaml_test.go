package sink

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/stretchr/testify/assert"
)

type yamlMockDiscovery struct {
	name string
}

func (m *yamlMockDiscovery) Discover()      {}
func (m *yamlMockDiscovery) Name() string   { return m.name }
func (m *yamlMockDiscovery) Source() string { return "mock" }

type yamlMockSinkObject struct {
	m common.SinkMap
}

func (m *yamlMockSinkObject) Map() common.SinkMap { return m.m }
func (m *yamlMockSinkObject) Options() any        { return nil }

func TestYaml_Process(t *testing.T) {
	logger := sreCommon.NewLogs()
	obs := common.NewObservability(logger, nil)
	dir := t.TempDir()
	options := YamlOptions{
		Dir: dir,
	}

	y := NewYaml(options, obs)
	assert.NotNil(t, y)

	discovery := &yamlMockDiscovery{name: "test-discovery"}
	sinkObject := &yamlMockSinkObject{
		m: common.SinkMap{
			"key": "value",
		},
	}

	y.Process(discovery, sinkObject)

	filePath := filepath.Join(dir, "test-discovery.yaml")
	assert.FileExists(t, filePath)

	data, err := os.ReadFile(filePath)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "key: value")
}

func TestYaml_New_EmptyDir(t *testing.T) {
	logger := sreCommon.NewLogs()
	obs := common.NewObservability(logger, nil)
	options := YamlOptions{
		Dir: "",
	}

	y := NewYaml(options, obs)
	assert.Nil(t, y)
}
