package sink

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"cloud.google.com/go/pubsub"
	"github.com/devopsext/discovery/common"
	"github.com/devopsext/discovery/discovery"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"google.golang.org/api/option"
)

type PubSubOptions struct {
	Enabled     bool
	Credentials string
	ProjectID   string
	Topic       string
	Topics      string
	Providers   []string
	Files       string
}

type PubSub struct {
	options       PubSubOptions
	logger        sreCommon.Logger
	observability *common.Observability
	client        *pubsub.Client
	topic         *pubsub.Topic
	topics        map[string]*pubsub.Topic
	files         map[string]string
}

type PubSubK8sWorkload struct {
	Source  string      `json:"source"`
	Type    string      `json:"type"`
	Cluster string      `json:"cluster"`
	Data    interface{} `json:"data"`
}

type PubSubLabel struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type PubSubLabels = []*PubSubLabel

func (ps *PubSub) gzipCompress(data []byte) ([]byte, error) {

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)

	_, err := zw.Write(data)
	if err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (ps *PubSub) publish(ctx context.Context, topic *pubsub.Topic, name string, data []byte, attrs ...map[string]string) {

	msg := &pubsub.Message{
		Data: data,
		Attributes: map[string]string{
			"name":   name,
			"source": "discovery",
		},
	}
	for _, a := range attrs {
		for k, v := range a {
			msg.Attributes[k] = v
		}
	}
	ps.logger.Debug("PubSub Sink has to publish %s %d bytes...", name, len(data))
	id, err := topic.Publish(ctx, msg).Get(ctx)
	if err != nil {
		ps.logger.Error("PubSub Sink publish error: %s", err)
		return
	}
	ps.logger.Debug("PubSub Sink published a message %s msg ID: %v", name, id)
}

func (ps *PubSub) processK8sWorkload(ctx context.Context, d common.Discovery, so common.SinkObject, topic *pubsub.Topic) error {

	name := d.Name()

	for kind, table := range so.Map() {
		if kind == "workload" {
			if t, ok := table.(common.SinkMap); ok {
				data, err := json.Marshal(PubSubK8sWorkload{
					Source:  name,
					Type:    "json",
					Cluster: so.Options().(discovery.K8sOptions).ClusterName,
					Data:    t,
				})
				if err != nil {
					return err
				}
				ps.publish(ctx, topic, name, data, map[string]string{"kind": kind})
			}
		}
	}
	return nil
}

func (ps *PubSub) processLabels(ctx context.Context, d common.Discovery, so common.SinkObject, topic *pubsub.Topic) error {

	name := d.Name()

	var arr []PubSubLabels
	for _, v := range so.Map() {
		if ks, ok := v.(common.Labels); ok {
			var lbs PubSubLabels
			for k1, v1 := range ks {
				lbs = append(lbs, &PubSubLabel{Name: k1, Value: fmt.Sprintf("%v", v1)})
			}
			arr = append(arr, lbs)
		}
	}
	data, err := json.Marshal(arr)
	if err != nil {
		return err
	}
	ps.publish(ctx, topic, name, data, nil)
	return nil
}

func (ps *PubSub) processNetbox(ctx context.Context, d common.Discovery, so common.SinkObject, topic *pubsub.Topic) error {

	name := d.Name()

	if len(so.Map()) == 0 {
		return nil
	}

	path := ps.files[name]
	if utils.IsEmpty(path) {
		return fmt.Errorf("PubSub Sink: file path for %s is not defined", name)
	}

	data, err := json.Marshal(so.Map())
	if err != nil {
		return err
	}

	f := discovery.PubSubMessagePayloadFile{
		Path: path,
		Data: data,
	}

	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}

	compressed, err := ps.gzipCompress(raw)
	if err != nil {
		return err
	}

	pm := make(map[string]*discovery.PubSubMessagePayload)
	pm[name] = &discovery.PubSubMessagePayload{
		Kind:        discovery.PubSubMessagePayloadKindFile,
		Compression: discovery.PubSubMessagePayloadCompressionGZip,
		Data:        compressed,
	}

	psm := discovery.PubSubMessage{
		Payload: pm,
	}

	psmd, err := json.Marshal(psm)
	if err != nil {
		return err
	}

	ps.publish(ctx, topic, name, psmd, nil)
	return nil
}

func (ps *PubSub) processDefault(ctx context.Context, d common.Discovery, so common.SinkObject, topic *pubsub.Topic) error {

	name := d.Name()

	if len(so.Map()) == 0 {
		return nil
	}
	data, err := json.Marshal(so.Map())
	if err != nil {
		return err
	}
	ps.publish(ctx, topic, name, data, nil)
	return nil
}

func (ps *PubSub) Process(d common.Discovery, so common.SinkObject) {

	name := d.Name()
	ctx := context.Background()

	var err error

	topic := ps.topic
	if t, ok := ps.topics[name]; ok {
		topic = t
	}
	if topic == nil {
		ps.logger.Error("PubSub Sink: topic for %s is not defined", name)
		return
	}

	switch name {
	case "K8s":
		err = ps.processK8sWorkload(ctx, d, so, topic)
	case "Labels":
		err = ps.processLabels(ctx, d, so, topic)
	case "Netbox":
		err = ps.processNetbox(ctx, d, so, topic)
	default:
		err = ps.processDefault(ctx, d, so, topic)
	}

	if err != nil {
		ps.logger.Error("PubSub Sink: %v", err)
		return
	}
}

func (ps *PubSub) Name() string {
	return "PubSub"
}

func (ps *PubSub) Providers() []string {
	return ps.options.Providers
}

func (ps *PubSub) Close() {
	if ps.topic != nil {
		ps.topic.Stop()
	}
	if ps.client != nil {
		ps.client.Close()
	}
}

func NewPubSub(options PubSubOptions, observability *common.Observability) *PubSub {

	logger := observability.Logs()

	if !options.Enabled {
		logger.Debug("PubSub sink is disabled. Skipped")
		return nil
	}

	if !options.Enabled || utils.IsEmpty(options.Credentials) || utils.IsEmpty(options.ProjectID) {
		logger.Debug("PubSub sink has no credentials or project ID. Skipped")
		return nil
	}

	var o option.ClientOption
	if _, err := os.Stat(options.Credentials); err == nil {
		o = option.WithCredentialsFile(options.Credentials)
	} else {
		o = option.WithCredentialsJSON([]byte(options.Credentials))
	}

	client, err := pubsub.NewClient(context.Background(), options.ProjectID, o)
	if err != nil {
		logger.Error("PubSub Sink: %v", err)
		return nil
	}

	topics := make(map[string]*pubsub.Topic)
	if !utils.IsEmpty(options.Topics) {
		m := utils.MapGetKeyValuesEx(options.Topics, ";", "=")
		for k, v := range m {
			topics[k] = client.Topic(v)
		}
	}

	if utils.IsEmpty(options.Topic) && len(topics) == 0 {
		logger.Debug("PubSub sink has no topic(s). Skipped")
		return nil
	}

	return &PubSub{
		options:       options,
		logger:        logger,
		observability: observability,
		client:        client,
		topic:         client.Topic(options.Topic),
		topics:        topics,
		files:         utils.MapGetKeyValues(options.Files),
	}
}
