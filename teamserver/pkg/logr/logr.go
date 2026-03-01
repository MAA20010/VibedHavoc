package logr

import (
	"os"
	"path/filepath"

	"Havoc/pkg/logger"
)

type Logr struct {
	// Path to directory where everything is going to be logged (user chat, input/output from agent)
	Path         string
	ListenerPath string
	AgentPath    string
	ServerPath   string

	LogrSendText func(text string)
}

var LogrInstance *Logr

func NewLogr(Server, Path string) *Logr {
	var (
		logr = new(Logr)
		err  error
	)

	logr.ServerPath = Server
	logr.Path = Server + "/" + Path
	logr.ListenerPath = Path + "/listener"
	logr.AgentPath = Path + "/agents"

	if _, err = os.Stat(Path); os.IsNotExist(err) {
		if err = os.MkdirAll(Path, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr folder: " + err.Error())
			return nil
		}
	} else {
		entries, err := os.ReadDir(Path)
		if err == nil {
			for _, entry := range entries {
				entryPath := filepath.Join(Path, entry.Name())
				// Preserve the agents directory (contains loot data)Add commentMore actions
				if entry.Name() != "agents" && entry.Name() != "loot_index.json" {
					err := os.RemoveAll(entryPath)
					if err != nil {
						logger.Error("Failed to clean up directory " + entry.Name() + ": " + err.Error())
					}
				}
			}
		} else {
			logger.Error("Failed to read loot directory: " + err.Error())
		}
	}

	if _, err = os.Stat(logr.AgentPath); os.IsNotExist(err) {
		if err = os.MkdirAll(logr.AgentPath, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr agent folder: " + err.Error())
			return nil
		}
	}

	if _, err = os.Stat(logr.ListenerPath); os.IsNotExist(err) {
		if err = os.MkdirAll(logr.ListenerPath, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr listener folder: " + err.Error())
			return nil
		}
	}

	return logr
}
