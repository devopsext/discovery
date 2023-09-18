package vendors

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"google.golang.org/api/option"
)

type PubSubOptions struct {
	Enabled                 bool
	Credentials             string
	ProjectID               string
	TopicID                 string
	SubscriptionName        string
	SubscriptionAckDeadline int
	SubscriptionRetention   int
	Schedule                string
	CMDBDir                 string
}

type PubSub struct {
	options       PubSubOptions
	logger        sreCommon.Logger
	observability *common.Observability
}

type File struct {
	Time time.Time   `json:"time"`
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

func (ps *PubSub) createSubscription(client *pubsub.Client, ctx context.Context, topic *pubsub.Topic, subID string) error {

	sub := client.Subscription(subID)
	ok, err := sub.Exists(ctx)
	if err != nil {
		return fmt.Errorf("an error occurred while checking the subscription status: %w", err)
	}
	if !ok {
		sub, err := client.CreateSubscription(ctx, subID, pubsub.SubscriptionConfig{
			Topic:             topic,
			AckDeadline:       time.Duration(ps.options.SubscriptionAckDeadline) * time.Second,
			RetentionDuration: time.Duration(ps.options.SubscriptionRetention) * time.Second,
		})
		if err != nil {
			return fmt.Errorf("an error occurred while creating the subscription: %w", err)
		}
		ps.logger.Debug("PubSub: created subscription: %v", sub)
	}
	return nil
}

func (ps *PubSub) updateCmdbFiles(data []byte) error {

	var cmdbMessage File
	bytesHashString := ""
	fileHashString := ""

	err := json.Unmarshal(data, &cmdbMessage)
	if err != nil {
		return err
	}

	cmdbDataBytes, err := json.Marshal(cmdbMessage.Data)
	if err != nil {
		return err
	}

	bytesHash := common.ByteMD5(cmdbDataBytes)
	if bytesHash != nil {
		bytesHashString = fmt.Sprintf("%x", bytesHash)
	}

	path := ps.options.CMDBDir + "/" + cmdbMessage.Type

	if _, err := os.Stat(path); err == nil {
		fileHash := common.FileMD5(path)
		if fileHash != nil {
			fileHashString = fmt.Sprintf("%x", fileHash)
		}
	}

	if fileHashString != bytesHashString {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = f.Write(cmdbDataBytes)
		if err != nil {
			return err
		}
		ps.logger.Debug("PubSub: file %s created or updated with md5 hash: %s", path, bytesHashString)
	} else {
		ps.logger.Debug("PubSub: File %s has the same md5 hash: %s, skipped", path, fileHashString)
	}

	return nil
}

func (ps *PubSub) pullMsgs(client *pubsub.Client, ctx context.Context, subID string) error {

	var received int32

	sub := client.Subscription(subID)

	err := sub.Receive(ctx, func(_ context.Context, msg *pubsub.Message) {
		err := ps.updateCmdbFiles(msg.Data)
		if err == nil {
			atomic.AddInt32(&received, 1)
			msg.Ack()
		} else {
			ps.logger.Error("PubSub: сouldn't process the message from pubsub with id: %s. Error: %w", msg.ID, err)
		}
	})
	if err != nil {
		return fmt.Errorf("an error occurred while pulling messages: %w", err)
	}
	ps.logger.Debug("PubSub: received %d messages", received)

	return nil
}

func (ps *PubSub) PubSubPull() {

	if _, err := os.Stat(ps.options.CMDBDir); err != nil {
		ps.logger.Error("PubSub: %v", err)
		return
	}

	var o option.ClientOption
	if _, err := os.Stat(ps.options.Credentials); err == nil {
		o = option.WithCredentialsFile(ps.options.Credentials)
	} else {
		o = option.WithCredentialsJSON([]byte(ps.options.Credentials))
	}

	ctx := context.Background()
	client, err := pubsub.NewClient(ctx, ps.options.ProjectID, o)
	if err != nil {
		ps.logger.Error("PubSub: %v", err)
		return
	}
	defer client.Close()

	topic := client.Topic(ps.options.TopicID)

	sub := ps.options.SubscriptionName
	err = ps.createSubscription(client, ctx, topic, sub)
	if err != nil {
		ps.logger.Error("PubSub: %v", err)
		return
	}

	err = ps.pullMsgs(client, ctx, sub)
	if err != nil {
		ps.logger.Error("PubSub: %v", err)
		return
	}
}

func NewPubSubPull(options PubSubOptions, observability *common.Observability) *PubSub {

	logger := observability.Logs()

	return &PubSub{
		options:       options,
		logger:        logger,
		observability: observability,
	}
}
