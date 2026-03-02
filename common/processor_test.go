package common

import (
	"testing"

	sreCommon "github.com/devopsext/sre/common"
	"github.com/stretchr/testify/mock"
)

// Mocks
type MockDiscovery struct {
	mock.Mock
}

func (m *MockDiscovery) Discover()      { m.Called() }
func (m *MockDiscovery) Name() string   { return m.Called().String(0) }
func (m *MockDiscovery) Source() string { return m.Called().String(0) }

type MockProcessor struct {
	mock.Mock
}

func (m *MockProcessor) Process(d Discovery, so SinkObject) { m.Called(d, so) }
func (m *MockProcessor) Name() string                       { return m.Called().String(0) }
func (m *MockProcessor) Providers() []string                { return m.Called().Get(0).([]string) }

type MockSink struct {
	mock.Mock
}

func (m *MockSink) Process(d Discovery, so SinkObject) { m.Called(d, so) }
func (m *MockSink) Name() string                       { return m.Called().String(0) }
func (m *MockSink) Providers() []string                { return m.Called().Get(0).([]string) }

type MockSinkObject struct {
	mock.Mock
}

func (m *MockSinkObject) Map() SinkMap { return m.Called().Get(0).(SinkMap) }
func (m *MockSinkObject) Options() any { return m.Called().Get(0) }

func TestProcessors_Process(t *testing.T) {
	obs := NewObservability(nil, nil)
	sinks := NewSinks(obs)
	ps := NewProcessors(obs, sinks)

	mockDiscovery := new(MockDiscovery)
	mockDiscovery.On("Name").Return("test-discovery")

	mockProcessor := new(MockProcessor)
	mockProcessor.On("Name").Return("test-processor")
	mockProcessor.On("Providers").Return([]string{"test-discovery"})
	mockProcessor.On("Process", mockDiscovery, mock.Anything).Return()

	mockSink := new(MockSink)
	mockSink.On("Name").Return("test-sink")
	mockSink.On("Providers").Return([]string{})
	mockSink.On("Process", mockDiscovery, mock.Anything).Return()

	ps.Add(mockProcessor)
	sinks.Add(mockSink)

	so := new(MockSinkObject)
	// Processors.Process calls p.Process(d, so) then ps.sinks.Process(d, so)

	ps.Process(mockDiscovery, so)

	mockProcessor.AssertCalled(t, "Process", mockDiscovery, so)
	mockSink.AssertCalled(t, "Process", mockDiscovery, so)
}

func TestProcessors_Process_Skipped(t *testing.T) {
	// sreCommon.NewLogs() returns a *Logs with no registered loggers — safe no-op, satisfies Logger interface.
	// This is required because the skip path at processor.go:36 calls ps.logger.Debug directly.
	obs := NewObservability(sreCommon.NewLogs(), nil)
	sinks := NewSinks(obs)
	ps := NewProcessors(obs, sinks)

	mockDiscovery := new(MockDiscovery)
	mockDiscovery.On("Name").Return("test-discovery")

	mockProcessor := new(MockProcessor)
	mockProcessor.On("Name").Return("test-processor")
	// Provider list does not include "test-discovery", so this processor should be skipped.
	mockProcessor.On("Providers").Return([]string{"other-discovery"})

	mockSink := new(MockSink)
	mockSink.On("Name").Return("test-sink")
	mockSink.On("Providers").Return([]string{})
	mockSink.On("Process", mockDiscovery, mock.Anything).Return()

	ps.Add(mockProcessor)
	sinks.Add(mockSink)

	so := new(MockSinkObject)
	ps.Process(mockDiscovery, so)

	// Processor must be skipped because "test-discovery" is not in ["other-discovery"].
	mockProcessor.AssertNotCalled(t, "Process", mockDiscovery, so)
	// Sinks are always called regardless of processor filtering.
	mockSink.AssertCalled(t, "Process", mockDiscovery, so)
}
