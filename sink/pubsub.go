package sink

import (
	"cloud.google.com/go/pubsub"
	"context"
	"encoding/json"
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"google.golang.org/api/option"
	"os"
)

type PubSubOptions struct {
	Enabled     bool
	Credentials string
	ProjectID   string
	TopicID     string
	Providers   []string
}

type PubSub struct {
	options       PubSubOptions
	logger        sreCommon.Logger
	observability *common.Observability
	client        *pubsub.Client
	topic         *pubsub.Topic
}

type PubSubPublishObject struct {
	Source string      `json:"source"`
	Type   string      `json:"type"`
	Data   interface{} `json:"data"`
}

type SCUpdateObject struct {
	Application string `json:"application"`
	Component   string `json:"component"`
	Instance    string `json:"instance"`
	Cluster     string `json:"cluster"`
	Environment string `json:"environment"`
	Kind        string `json:"type"`
	Resource    string `json:"resource"`
}

type SCUpdateObjects []SCUpdateObject

type SCUpdateObjectMap map[string]SCUpdateObject

func sinkMapToSCUpdateObjects(sinkMap common.SinkMap) *SCUpdateObjects {

	if sinkMap == nil {
		return nil
	}

	om := make(SCUpdateObjectMap)
	res := make(SCUpdateObjects, 0)

	lm := common.ConvertSyncMapToLabelsMap(sinkMap)

	for k, v := range lm {
		if v == nil {
			continue
		}
		if _, found := om[k]; !found {
			om[k] = SCUpdateObject{
				Application: v["application"],
				Component:   v["component"],
				Instance:    k,
				Cluster:     v["cluster"],
				Environment: v["environment"],
				Kind:        v["kind"],
				Resource:    v["node"],
			}
		} else {
			t := om[k]
			t.Resource = t.Resource + "," + v["node"]
			om[k] = t
		}
	}

	for _, object := range om {
		res = append(res, object)
	}

	return &res
}

func (ps *PubSub) Process(d common.Discovery, so common.SinkObject) {
	data, err := json.Marshal(PubSubPublishObject{
		Source: d.Name(),
		Type:   "json",
		Data:   sinkMapToSCUpdateObjects(so.Map()),
	})
	if err != nil {
		ps.logger.Error("PubSub Sink: %v", err)
		return
	}

	ps.logger.Debug("PubSub has to publish %d bytes...", len(data))

	err = ps.publish(context.Background(), data)
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

func (ps *PubSub) publish(ctx context.Context, data []byte) error {

	msg := &pubsub.Message{
		Data: data,
		Attributes: map[string]string{
			"source": "discovery",
		},
	}

	_, err := ps.topic.Publish(ctx, msg).Get(ctx)
	if err != nil {
		return err
	}

	return nil
}

func NewPubSub(options PubSubOptions, observability *common.Observability) *PubSub {

	logger := observability.Logs()

	if !options.Enabled {
		logger.Debug("PubSub sink is not enabled. Skipped")
		return nil
	}

	if options.Credentials == "" {
		logger.Debug("PubSub sink has no credentials. Skipped")
		return nil
	}

	if options.ProjectID == "" {
		logger.Debug("PubSub sink has no project id. Skipped")
		return nil
	}

	if options.TopicID == "" {
		logger.Debug("PubSub sink has no topic id. Skipped")
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

	topic := client.Topic(options.TopicID)

	return &PubSub{
		options:       options,
		logger:        logger,
		observability: observability,
		client:        client,
		topic:         topic,
	}
}
