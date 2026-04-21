package sink

import (
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
)

type testDiscovery struct {
	name string
}

func (m *testDiscovery) Discover()      {}
func (m *testDiscovery) Name() string   { return m.name }
func (m *testDiscovery) Source() string { return "mock" }

type testSinkObject struct {
	m common.SinkMap
}

func (m *testSinkObject) Map() common.SinkMap { return m.m }
func (m *testSinkObject) Options() any        { return nil }

func newTestObs() *common.Observability {
	return common.NewObservability(sreCommon.NewLogs(), nil)
}
