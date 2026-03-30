package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"cloud.google.com/go/pubsub"
	"google.golang.org/api/option"
)

type Transport struct {
	client     *pubsub.Client
	sub        *pubsub.Subscription
	topic      *pubsub.Topic
	ctx        context.Context
	cancel     context.CancelFunc
	instanceID string
	agentID    string
}

type Config struct {
	ProjectID         string `json:"project_id"`
	ResultsTopic      string `json:"results_topic"`
	TasksSubscription string `json:"subscription_id"`
	CredentialsB64JSON string `json:"credentials_b64_json"`
}

func NewTransport(cfg *Config, instanceID, agentID string) (*Transport, error) {
	ctx, cancel := context.WithCancel(context.Background())

	var opts []option.ClientOption
	if cfg.CredentialsB64JSON != "" {
		credJSON, err := base64.StdEncoding.DecodeString(cfg.CredentialsB64JSON)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to decode credentials JSON: %w", err)
		}
		opts = append(opts, option.WithCredentialsJSON(credJSON))
	}

	client, err := pubsub.NewClient(ctx, cfg.ProjectID, opts...)
	if err != nil {
		cancel()
		return nil, err
	}

	tasksSubscription := client.Subscription(cfg.TasksSubscription)
	exists, err := tasksSubscription.Exists(ctx)
	if err != nil {
		cancel()
		client.Close()
		return nil, fmt.Errorf("failed to check subscription %s: %w", cfg.TasksSubscription, err)
	}
	if !exists {
		cancel()
		client.Close()
		return nil, fmt.Errorf("subscription %s does not exist", cfg.TasksSubscription)
	}

	tasksSubscription.ReceiveSettings = pubsub.ReceiveSettings{
		MaxOutstandingMessages: 1000,
		NumGoroutines:          10,
	}

	resultsTopic := client.Topic(cfg.ResultsTopic)
	resultsTopic.PublishSettings = pubsub.PublishSettings{
		DelayThreshold: 10 * time.Millisecond,
		CountThreshold: 1,
		ByteThreshold:  1e6,
	}

	return &Transport{
		client:     client,
		sub:        tasksSubscription,
		topic:      resultsTopic,
		ctx:        ctx,
		cancel:     cancel,
		instanceID: instanceID,
		agentID:    agentID,
	}, nil
}

func (t *Transport) Listen(handler func(task map[string]interface{}) map[string]interface{}) error {
	return t.sub.Receive(t.ctx, func(ctx context.Context, msg *pubsub.Message) {
		// Check if this message is for us
		targetInstance := msg.Attributes["instance_id"]
		if targetInstance != "" && targetInstance != t.instanceID {
			msg.Nack()
			return
		}

		// Parse incoming task
		var task map[string]interface{}
		if err := json.Unmarshal(msg.Data, &task); err != nil {
			msg.Nack()
			return
		}

		result := handler(task)

		// Send response if we have one
		if result != nil {
			data, _ := json.Marshal(result)
			t.topic.Publish(t.ctx, &pubsub.Message{Data: data})
		}

		msg.Ack()
	})
}

func (t *Transport) SendRaw(base64Message string) error {
	wrapper := map[string]interface{}{
		"message":   base64Message,
		"sender_id": t.instanceID,
		"client_id": t.agentID,
		"to_server": true,
	}
	wrapperData, err := json.Marshal(wrapper)
	if err != nil {
		return fmt.Errorf("failed to marshal wrapper: %w", err)
	}
	result := t.topic.Publish(t.ctx, &pubsub.Message{Data: wrapperData})
	_, err = result.Get(t.ctx)
	return err
}

func (t *Transport) Close() error {
	t.cancel()
	t.topic.Stop()
	return t.client.Close()
}
