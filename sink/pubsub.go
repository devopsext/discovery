package sink

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"cloud.google.com/go/pubsub"
	"github.com/devopsext/discovery/common"
	"github.com/devopsext/discovery/discovery"
	sreCommon "github.com/devopsext/sre/common"
	"google.golang.org/api/option"
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

func (ps *PubSub) Process(d common.Discovery, so common.SinkObject) {

	name := d.Name()
	ctx := context.Background()

	switch name {
	case "K8s":
		for kind, table := range so.Map() {
			switch kind {
			case "workload":
				t, ok := table.(common.SinkMap)
				if ok {
					data, err := json.Marshal(PubSubK8sWorkload{
						Source:  name,
						Type:    "json",
						Cluster: so.Options().(discovery.K8sOptions).ClusterName,
						Data:    t,
					})
					if err != nil {
						ps.logger.Error("PubSub Sink: %v", err)
						return
					}

					ps.logger.Debug("PubSub Sink has to publish %s %s %d bytes...", name, kind, len(data))

					err = ps.publish(ctx, data, map[string]string{"name": name, "kind": kind})
					if err != nil {
						ps.logger.Error("PubSub Sink publish error: %s", err)
						return
					}
				}
			}
		}

	case "Labels":

		arr := make([]PubSubLabels, 0)
		for _, v := range so.Map() {
			ks, ok := v.(common.Labels)
			if !ok {
				continue
			}

			lbs := PubSubLabels{}
			for k1, v1 := range ks {
				lb := &PubSubLabel{
					Name:  k1,
					Value: fmt.Sprintf("%v", v1),
				}
				lbs = append(lbs, lb)
			}
			arr = append(arr, lbs)
		}

		data, err := json.Marshal(arr)
		if err != nil {
			ps.logger.Error("PubSub Sink marshall error: %s", err)
			return
		}

		ps.logger.Debug("PubSub has to publish %s %d bytes...", name, len(data))

		err = ps.publish(ctx, data, map[string]string{"name": name})
		if err != nil {
			ps.logger.Error("PubSub Sink publish error: %s", err)
			return
		}

	default:
		ps.logger.Debug("PubSub Sink: %s is not supported", name)
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

func (ps *PubSub) publish(ctx context.Context, data []byte, attributes ...map[string]string) error {

	msg := &pubsub.Message{
		Data: data,
		Attributes: map[string]string{
			"source": "discovery",
		},
	}
	if len(attributes) > 0 {
		for _, a := range attributes {
			for k, v := range a {
				msg.Attributes[k] = v
			}
		}
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
