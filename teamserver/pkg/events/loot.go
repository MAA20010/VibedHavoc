package events

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"Havoc/pkg/logr"
	"Havoc/pkg/packager"
)

func SendLootIndex(indices []logr.LootIndex) packager.Package {
	// Convert indices to JSON
	jsonData, err := json.Marshal(indices)
	if err != nil {
		return packager.Package{}
	}

	return packager.Package{
		Head: packager.Head{
			Event: packager.Type.Loot.Type,
			Time:  time.Now().Format("02/01/2006 15:04:05"),
		},

		Body: packager.Body{
			SubEvent: packager.Type.Loot.SyncAll,
			Info: map[string]any{
				"LootData": string(jsonData),
			},
		},
	}
}

func SendLootAgentIndex(agentID string, index *logr.LootIndex) packager.Package {
	// Convert index to JSON
	jsonData, err := json.Marshal(index)
	if err != nil {
		return packager.Package{}
	}

	return packager.Package{
		Head: packager.Head{
			Event: packager.Type.Loot.Type,
			Time:  time.Now().Format("02/01/2006 15:04:05"),
		},

		Body: packager.Body{
			SubEvent: packager.Type.Loot.ListAgent,
			Info: map[string]any{
				"AgentID":  agentID,
				"LootData": string(jsonData),
			},
		},
	}
}

func SendLootFile(agentID, relativePath string, fileData []byte, metadata *logr.LootMetadata) packager.Package {
	// Convert metadata to JSON
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return packager.Package{}
	}

	return packager.Package{
		Head: packager.Head{
			Event: packager.Type.Loot.Type,
			Time:  time.Now().Format("02/01/2006 15:04:05"),
		},

		Body: packager.Body{
			SubEvent: packager.Type.Loot.GetFile,
			Info: map[string]any{
				"AgentID":      agentID,
				"RelativePath": relativePath,
				"FileData":     base64.StdEncoding.EncodeToString(fileData),
				"Metadata":     string(metadataJSON),
			},
		},
	}
} 