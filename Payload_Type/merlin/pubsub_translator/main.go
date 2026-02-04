package main

import (
	"encoding/json"

	"github.com/MythicMeta/MythicContainer"
	translationstructs "github.com/MythicMeta/MythicContainer/translation_structs"
)

// merlinPubSubTranslator implements Mythic's translation container interface
// for the Merlin PubSub agent. It mirrors the simple JSON-in/JSON-out behavior
var merlinPubSubTranslator = translationstructs.TranslationContainer{
	Name: "pubsub_translator",
	Description: "Go translation service for Merlin PubSub agent. " +
		"Converts between raw JSON bytes on the wire and Mythic's internal message format.",
	Author: "TN Tech Capstone Team",

	// Agent -> Mythic
	CustomToMythicC2FormatFunc: func(input translationstructs.TrCustomMessageToMythicC2FormatMessage) translationstructs.TrCustomMessageToMythicC2FormatMessageResponse {
		resp := translationstructs.TrCustomMessageToMythicC2FormatMessageResponse{
			Success: true,
		}

		// The PubSub agent sends UTF-8 JSON bytes; decode to Mythic's expected map
		var msg map[string]interface{}
		if err := json.Unmarshal(input.Message, &msg); err != nil {
			resp.Success = false
			resp.Error = "failed to decode/parse agent message: " + err.Error()
			return resp
		}

		resp.Message = msg
		return resp
	},

	// Mythic -> Agent
	MythicC2ToCustomFormatFunc: func(input translationstructs.TrMythicC2ToCustomMessageFormatMessage) translationstructs.TrMythicC2ToCustomMessageFormatMessageResponse {
		resp := translationstructs.TrMythicC2ToCustomMessageFormatMessageResponse{
			Success: true,
		}

		wire, err := json.Marshal(input.Message)
		if err != nil {
			resp.Success = false
			resp.Error = "failed to encode Mythic message: " + err.Error()
			return resp
		}

		resp.Message = wire
		return resp
	},

	// No encryption — return nil keys so Mythic delegates entirely
	// to this translation container for encoding/decoding.
	GenerateEncryptionKeysFunc: func(input translationstructs.TrGenerateEncryptionKeysMessage) translationstructs.TrGenerateEncryptionKeysMessageResponse {
		return translationstructs.TrGenerateEncryptionKeysMessageResponse{
			Success:       true,
			EncryptionKey: nil,
			DecryptionKey: nil,
		}
	},
}

func main() {
	// Register this translation container definition with the Mythic container runtime
	translationstructs.AllTranslationData.Get(merlinPubSubTranslator.Name).
		AddTranslationDefinition(merlinPubSubTranslator)

	// Start the Mythic translation container service
	MythicContainer.StartAndRunForever([]MythicContainer.MythicServices{
		MythicContainer.MythicServiceTranslationContainer,
	})
}


