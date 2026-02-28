package sink

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/devopsext/discovery/common"
	"github.com/stretchr/testify/assert"
)

func TestYaml_Process(t *testing.T) {
	obs := newTestObs()
	dir := t.TempDir()
	options := YamlOptions{
		Dir: dir,
	}

	y := NewYaml(options, obs)
	assert.NotNil(t, y)

	discovery := &testDiscovery{name: "test-discovery"}
	sinkObject := &testSinkObject{
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
	obs := newTestObs()
	options := YamlOptions{
		Dir: "",
	}

	y := NewYaml(options, obs)
	assert.Nil(t, y)
}
