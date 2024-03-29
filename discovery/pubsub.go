package discovery

import (
	"context"
	"encoding/json"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"google.golang.org/api/option"
)

type PubSubOptions struct {
	Credentials  string
	Project      string
	Topic        string
	Subscription string
	AckDeadline  int
	Retention    int
}

type PubSub struct {
	options       PubSubOptions
	logger        sreCommon.Logger
	observability *common.Observability
	sinks         *common.Sinks
	client        *pubsub.Client
}

type PubSubMessagePayloadFile struct {
	Path string `json:"path"`
	Data []byte `json:"data"`
}

type PubSubMessagePayloadFiles = []*PubSubMessagePayloadFile

type PubSubMessagePayloadKind = int

const (
	PubSubMessagePayloadKindUnknown int = iota
	PubSubMessagePayloadKindFile
	PubSubMessagePayloadKindFiles
)

type PubSubMessagePayloadCompression = int

const (
	PubSubMessagePayloadCompressionNone int = iota
	PubSubMessagePayloadCompressionGZip
)

type PubSubMessagePayload struct {
	Kind        PubSubMessagePayloadKind        `json:"kind"`
	Compression PubSubMessagePayloadCompression `json:"compression"`
	Data        []byte                          `json:"data"`
}

type PubSubMessage struct {
	Payload map[string]*PubSubMessagePayload `json:"payload"`
}

type PubSubSinkObject struct {
	sinkMap common.SinkMap
	pubsub  *PubSub
}

func (so *PubSubSinkObject) Map() common.SinkMap {
	return so.sinkMap
}

func (so *PubSubSinkObject) Options() interface{} {
	return so.pubsub.options
}

func (ps *PubSub) Name() string {
	return "PubSub"
}

func (ps *PubSub) Source() string {
	return ""
}

func (ps *PubSub) Discover() {

	ps.logger.Debug("PubSub discovery by topic: %s", ps.options.Topic)

	ctx := context.Background()
	topic := ps.client.Topic(ps.options.Topic)
	subID := ps.options.Subscription

	sub := ps.client.Subscription(subID)
	exists, err := sub.Exists(ctx)
	if err != nil {
		ps.logger.Debug("PubSub subscription %s error: %s", subID, err)
		return
	}

	if !exists {
		sub, err = ps.client.CreateSubscription(ctx, subID, pubsub.SubscriptionConfig{
			Topic:             topic,
			AckDeadline:       time.Duration(ps.options.AckDeadline) * time.Second,
			RetentionDuration: time.Duration(ps.options.Retention) * time.Second,
		})
		if err != nil {
			ps.logger.Debug("PubSub subscription %s creation error: %s", subID, err)
			return
		}
		ps.logger.Debug("PubSub subscription %s was created", subID)
	}

	err = sub.Receive(ctx, func(_ context.Context, msg *pubsub.Message) {

		var pm PubSubMessage
		err := json.Unmarshal(msg.Data, &pm)
		if err != nil {
			msg.Nack()
			ps.logger.Error("PubSub couldn't unmarshal from %s error: %s", subID, err)
			return
		}

		m := make(map[string]interface{})

		for k, v := range pm.Payload {

			if v.Kind == PubSubMessagePayloadKindUnknown {
				ps.logger.Error("PubSub couldn't process unknown message from %s error: %s", subID, err)
				continue
			}
			m[k] = v
		}

		ps.sinks.Process(ps, &PubSubSinkObject{
			sinkMap: m,
			pubsub:  ps,
		})
		msg.Ack()
	})

	if err != nil {
		ps.logger.Error("PubSub couldn't receive messages from %s error: %s", subID, err)
		return
	}
}

func NewPubSub(options PubSubOptions, observability *common.Observability, sinks *common.Sinks) *PubSub {

	logger := observability.Logs()

	if utils.IsEmpty(options.Credentials) || utils.IsEmpty(options.Topic) ||
		utils.IsEmpty(options.Subscription) || utils.IsEmpty(options.Project) {
		logger.Debug("PubSub is disabled. Skipped")
		return nil
	}

	data, err := utils.Content(options.Credentials)
	if err != nil {
		logger.Debug("PubSub credentials error: %s", err)
		return nil
	}

	o := option.WithCredentialsJSON(data)

	client, err := pubsub.NewClient(context.Background(), options.Project, o)
	if err != nil {
		logger.Error("PubSub new client error: %s", err)
		return nil
	}

	return &PubSub{
		options:       options,
		logger:        logger,
		observability: observability,
		sinks:         sinks,
		client:        client,
	}
}
