package logr

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"Havoc/pkg/common"
	"Havoc/pkg/logger"
)

// LootMetadata represents metadata for loot items
type LootMetadata struct {
	Type         string `json:"type"`
	Filename     string `json:"filename"`
	RelativePath string `json:"relative_path"`
	FullPath     string `json:"full_path"` // Full path to the actual file on disk
	Operator     string `json:"operator"`
	Timestamp    string `json:"timestamp"`
	Size         int64  `json:"size"`
	ExternalIP   string `json:"external_ip,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	Username     string `json:"username,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	AgentID      string `json:"agent_id"` // Add agent ID to each item
}

// MasterLootIndex represents the complete loot index for all agents across all sessions
type MasterLootIndex struct {
	Items []LootMetadata `json:"items"`
}

// Legacy LootIndex for compatibility (can be removed later)
type LootIndex struct {
	AgentID string         `json:"agent_id"`
	Items   []LootMetadata `json:"items"`
}

func (l Logr) AddAgentInput(AgentType, AgentID, User, TaskID, Input string, time string) {
	var (
		DemonPath    = l.AgentPath + "/" + AgentID
		DemonLogFile = DemonPath + "/Console_" + AgentID + ".log"
		InputString  string
	)

	// check if we don't have a path traversal
	path := filepath.Clean(DemonLogFile)
	if !strings.HasPrefix(path, DemonPath) {
		logger.Error("File didn't started with agent loot path. abort")
		return
	}

	if _, err := os.Stat(DemonPath); os.IsNotExist(err) {
		if err = os.Mkdir(DemonPath, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr demon " + AgentID + " folder: " + err.Error())
			return
		}
	}

	f, err := os.OpenFile(DemonLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Error("Failed to open log file [" + DemonLogFile + "]: " + err.Error())
		return
	}
	defer f.Close()

	InputString = fmt.Sprintf("\n[Time: %v] [User: %v] [TaskID: %v] %v => %v\n", time, User, TaskID, AgentType, Input)

	_, err = f.Write([]byte(InputString))
	if err != nil {
		logger.Error("Failed to write to File [" + DemonLogFile + "]: " + err.Error())
		return
	}
}

func (l Logr) AddAgentRaw(AgentID, Raw string) {
	var (
		DemonPath    = l.AgentPath + "/" + AgentID
		DemonLogFile = DemonPath + "/Console_" + AgentID + ".log"
	)

	// check if we don't have a path traversal
	path := filepath.Clean(DemonLogFile)
	if !strings.HasPrefix(path, DemonPath) {
		logger.Error("File didn't started with agent loot path. abort")
		return
	}

	if _, err := os.Stat(DemonPath); os.IsNotExist(err) {
		if err = os.Mkdir(DemonPath, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr demon " + AgentID + " folder: " + err.Error())
			return
		}
	}

	f, err := os.OpenFile(DemonLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Error("Failed to open log file [" + DemonLogFile + "]: " + err.Error())
		return
	}
	defer f.Close()

	_, err = f.Write([]byte(Raw))
	if err != nil {
		logger.Error("Failed to write to File [" + DemonLogFile + "]: " + err.Error())
		return
	}
}

func (l Logr) DemonAddOutput(DemonID string, Output map[string]string, time string) {
	var (
		DemonPath    = l.AgentPath + "/" + filepath.Clean(DemonID)
		DemonLogFile = DemonPath + "/Console_" + DemonID + ".log"
	)

	// check if we don't have a path traversal
	path := filepath.Clean(DemonLogFile)
	if !strings.HasPrefix(path, DemonPath) {
		logger.Error("File didn't started with agent loot path. abort")
		return
	}

	if _, err := os.Stat(DemonPath); os.IsNotExist(err) {
		if err = os.Mkdir(DemonPath, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr demon " + DemonID + " folder: " + err.Error())
			return
		}
	}

	f, err := os.OpenFile(DemonLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Error("Failed to open log file [" + DemonLogFile + "]: " + err.Error())
		return
	}
	defer f.Close()

	var OutputString string

	if len(Output["Message"]) > 0 {

		if Output["Type"] == "Good" {
			OutputString = fmt.Sprintf("[%v] [+] %v\n", time, Output["Message"])
		} else if Output["Type"] == "Error" {
			OutputString = fmt.Sprintf("[%v] [-] %v\n", time, Output["Message"])
		} else if Output["Type"] == "Info" {
			OutputString = fmt.Sprintf("[%v] [*] %v\n", time, Output["Message"])
		} else {
			OutputString = fmt.Sprintf("[%v] [^] %v\n", time, Output["Message"])
		}

	}

	if len(Output["Output"]) > 0 {
		OutputString += Output["Output"]
	}

	_, err = f.Write([]byte(OutputString))
	if err != nil {
		logger.Error("Failed to write to File [" + DemonLogFile + "]: " + err.Error())
		return
	}
}

func (l Logr) DemonAddDownloadedFile(DemonID, FileName string, FileBytes []byte) {
	l.DemonAddDownloadedFileWithOperator(DemonID, FileName, FileBytes, "unknown")
}

func (l Logr) DemonAddDownloadedFileWithOperator(DemonID, FileName string, FileBytes []byte, operator string) {
	var (
		DemonPath        = l.AgentPath + "/" + DemonID
		DemonDownloadDir = DemonPath + "/Download"
		DemonDownload    = DemonDownloadDir + "/" + FileName
	)

	// check if we don't have a path traversal
	path := filepath.Clean(DemonDownload)
	if !strings.HasPrefix(path, DemonDownloadDir) {
		logger.Error("File didn't started with agent download path. abort")
		return
	}

	if _, err := os.Stat(DemonPath); os.IsNotExist(err) {
		if err = os.Mkdir(DemonPath, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr demon " + DemonID + " folder: " + err.Error())
			return
		}
	}

	if _, err := os.Stat(DemonDownloadDir); os.IsNotExist(err) {
		if err = os.Mkdir(DemonDownloadDir, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr demon " + DemonID + " download folder: " + err.Error())
			return
		}
	}

	f, err := os.Create(DemonDownload)
	if err != nil {
		logger.Error("Failed to create file: " + err.Error())
		return
	}

	defer f.Close()

	_, err = f.Write(FileBytes)
	if err != nil {
		logger.Error("Failed to write file: " + err.Error())
		return
	}

	// Add metadata entry to master loot index
	metadata := LootMetadata{
		Type:         "download",
		Filename:     FileName,
		RelativePath: "Download/" + FileName,
		FullPath:     DemonDownload,
		Operator:     operator,
		Timestamp:    time.Now().Format("02/01/2006 15:04:05"),
		Size:         int64(len(FileBytes)),
		AgentID:      DemonID,
	}

	if err := l.addToMasterLootIndex(metadata); err != nil {
		logger.Error("Failed to add loot metadata for download: " + err.Error())
		// Don't fail the whole operation if metadata fails
	}
}

// DemonAddDownloadedFileWithOperatorAndContext saves a download file with full agent context
func (l Logr) DemonAddDownloadedFileWithOperatorAndContext(DemonID, FileName string, FileBytes []byte, operator string, externalIP, hostname, username string) {
	var (
		DemonPath        = l.AgentPath + "/" + DemonID
		DemonDownloadDir = DemonPath + "/Download"
		DemonDownload    = DemonDownloadDir + "/" + FileName
	)

	// check if we don't have a path traversal
	path := filepath.Clean(DemonDownload)
	if !strings.HasPrefix(path, DemonDownloadDir) {
		logger.Error("File didn't started with agent download path. abort")
		return
	}

	if _, err := os.Stat(DemonPath); os.IsNotExist(err) {
		if err = os.Mkdir(DemonPath, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr demon " + DemonID + " folder: " + err.Error())
			return
		}
	}

	if _, err := os.Stat(DemonDownloadDir); os.IsNotExist(err) {
		if err = os.Mkdir(DemonDownloadDir, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr demon " + DemonID + " download folder: " + err.Error())
			return
		}
	}

	f, err := os.Create(DemonDownload)
	if err != nil {
		logger.Error("Failed to create file: " + err.Error())
		return
	}

	defer f.Close()

	_, err = f.Write(FileBytes)
	if err != nil {
		logger.Error("Failed to write file: " + err.Error())
		return
	}

	// Add metadata with full agent context to master loot index
	metadata := LootMetadata{
		Type:         "download",
		Filename:     FileName,
		RelativePath: "Download/" + FileName,
		FullPath:     DemonDownload,
		Operator:     operator,
		Timestamp:    time.Now().Format("02/01/2006 15:04:05"),
		Size:         int64(len(FileBytes)),
		ExternalIP:   externalIP,
		Hostname:     hostname,
		Username:     username,
		SessionID:    DemonID,
		AgentID:      DemonID,
	}

	if err := l.addToMasterLootIndex(metadata); err != nil {
		logger.Error("Failed to add loot metadata for download: " + err.Error())
		// Don't fail the whole operation if metadata fails
	}
}

func (l Logr) DemonSaveScreenshot(DemonID, Name string, BmpBytes []byte) error {
	return l.DemonSaveScreenshotWithOperator(DemonID, Name, "unknown", BmpBytes)
}

func (l Logr) DemonSaveScreenshotWithOperator(DemonID, Name, operator string, BmpBytes []byte) error {
	var (
		DemonPath          = l.AgentPath + "/" + DemonID
		DemonScreenshotDir = DemonPath + "/Screenshots"
		DemonScreenshot    = DemonScreenshotDir + "/" + Name
	)

	// check if we don't have a path traversal
	path := filepath.Clean(DemonScreenshot)
	if !strings.HasPrefix(path, DemonScreenshotDir) {
		logger.Error("File didn't started with agent screenshot path. abort")
		return errors.New("file didn't started with agent screenshot path. abort")
	}

	if _, err := os.Stat(DemonPath); os.IsNotExist(err) {
		if err = os.Mkdir(DemonPath, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr demon " + DemonID + " folder: " + err.Error())
			return errors.New("Failed to create Logr demon " + DemonID + " folder: " + err.Error())
		}
	}

	if _, err := os.Stat(DemonScreenshotDir); os.IsNotExist(err) {
		if err = os.Mkdir(DemonScreenshotDir, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr demon " + DemonID + " screenshot folder: " + err.Error())
			return errors.New("Failed to create Logr demon " + DemonID + " screenshot folder: " + err.Error())
		}
	}

	f, err := os.Create(DemonScreenshot)
	if err != nil {
		logger.Error("Failed to create file: " + err.Error())
		return errors.New("Failed to create file: " + err.Error())
	}

	defer f.Close()

	pngBytes := common.Bmp2Png(BmpBytes)
	_, err = f.Write(pngBytes)
	if err != nil {
		logger.Error("Failed to write png file: " + err.Error())
		return errors.New("Failed to write png file: " + err.Error())
	}

	// Add metadata entry to master loot index
	metadata := LootMetadata{
		Type:         "screenshot",
		Filename:     Name,
		RelativePath: "Screenshots/" + Name,
		FullPath:     DemonScreenshot,
		Operator:     operator,
		Timestamp:    time.Now().Format("02/01/2006 15:04:05"),
		Size:         int64(len(pngBytes)),
		AgentID:      DemonID,
	}

	if err := l.addToMasterLootIndex(metadata); err != nil {
		logger.Error("Failed to add loot metadata for screenshot: " + err.Error())
		// Don't fail the whole operation if metadata fails
	}

	return nil
}

// DemonSaveScreenshotWithOperatorAndContext saves a screenshot with full agent context
func (l Logr) DemonSaveScreenshotWithOperatorAndContext(DemonID, Name, operator string, BmpBytes []byte, externalIP, hostname, username string) error {
	var (
		DemonPath          = l.AgentPath + "/" + DemonID
		DemonScreenshotDir = DemonPath + "/Screenshots"
		DemonScreenshot    = DemonScreenshotDir + "/" + Name
	)

	// check if we don't have a path traversal
	path := filepath.Clean(DemonScreenshot)
	if !strings.HasPrefix(path, DemonScreenshotDir) {
		logger.Error("File didn't started with agent screenshot path. abort")
		return errors.New("file didn't started with agent screenshot path. abort")
	}

	if _, err := os.Stat(DemonPath); os.IsNotExist(err) {
		if err = os.Mkdir(DemonPath, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr demon " + DemonID + " folder: " + err.Error())
			return errors.New("Failed to create Logr demon " + DemonID + " folder: " + err.Error())
		}
	}

	if _, err := os.Stat(DemonScreenshotDir); os.IsNotExist(err) {
		if err = os.Mkdir(DemonScreenshotDir, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr demon " + DemonID + " screenshot folder: " + err.Error())
			return errors.New("Failed to create Logr demon " + DemonID + " screenshot folder: " + err.Error())
		}
	}

	f, err := os.Create(DemonScreenshot)
	if err != nil {
		logger.Error("Failed to create file: " + err.Error())
		return errors.New("Failed to create file: " + err.Error())
	}

	defer f.Close()

	pngBytes := common.Bmp2Png(BmpBytes)
	_, err = f.Write(pngBytes)
	if err != nil {
		logger.Error("Failed to write png file: " + err.Error())
		return errors.New("Failed to write png file: " + err.Error())
	}

	// Add metadata with full agent context to master loot index
	metadata := LootMetadata{
		Type:         "screenshot",
		Filename:     Name,
		RelativePath: "Screenshots/" + Name,
		FullPath:     DemonScreenshot,
		Operator:     operator,
		Timestamp:    time.Now().Format("02/01/2006 15:04:05"),
		Size:         int64(len(pngBytes)),
		ExternalIP:   externalIP,
		Hostname:     hostname,
		Username:     username,
		SessionID:    DemonID,
		AgentID:      DemonID,
	}

	if err := l.addToMasterLootIndex(metadata); err != nil {
		logger.Error("Failed to add loot metadata for screenshot: " + err.Error())
		// Don't fail the whole operation if metadata fails
	}

	return nil
}

// AddLootMetadata adds metadata for a loot item to the agent's loot index
func (l Logr) AddLootMetadata(agentID, lootType, filename, operator string, size int64) error {
	var (
		agentPath = l.AgentPath + "/" + agentID
		indexPath = agentPath + "/loot_index.json"
	)

	// Create agent directory if it doesn't exist
	if _, err := os.Stat(agentPath); os.IsNotExist(err) {
		if err := os.Mkdir(agentPath, os.ModePerm); err != nil {
			return err
		}
	}

	// Load existing index or create new one
	var index LootIndex
	if data, err := ioutil.ReadFile(indexPath); err == nil {
		if err := json.Unmarshal(data, &index); err != nil {
			return err
		}
	} else {
		index = LootIndex{AgentID: agentID, Items: []LootMetadata{}}
	}

	// Add new metadata with consistent date format
	relativePath := ""
	if lootType == "screenshot" {
		relativePath = "Screenshots/" + filename
	} else if lootType == "download" {
		relativePath = "Download/" + filename
	}

	metadata := LootMetadata{
		Type:         lootType,
		Filename:     filename,
		RelativePath: relativePath,
		Operator:     operator,
		Timestamp:    time.Now().Format("02/01/2006 15:04:05"), // Standardized format
		Size:         size,
		AgentID:      agentID,
	}

	index.Items = append(index.Items, metadata)

	// Save updated index
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(indexPath, data, 0644)
}

// AddLootMetadataWithContext adds metadata for a loot item with additional agent context
func (l Logr) AddLootMetadataWithContext(agentID, lootType, filename, operator string, size int64) error {
	// For now, use the basic AddLootMetadata and then enhance with context
	// TODO: Get agent context from teamserver instance or pass it as parameters
	metadata := LootMetadata{
		Type:         lootType,
		Filename:     filename,
		RelativePath: "",
		Operator:     operator,
		Timestamp:    time.Now().Format("02/01/2006 15:04:05"),
		Size:         size,
		SessionID:    agentID, // Use agent ID as session identifier
		AgentID:      agentID,
		// TODO: Add external IP, hostname, username when available
	}

	if lootType == "screenshot" {
		metadata.RelativePath = "Screenshots/" + filename
	} else if lootType == "download" {
		metadata.RelativePath = "Download/" + filename
	}

	return l.addLootMetadataEntry(agentID, metadata)
}

// AddLootMetadataEntry is a public wrapper for adding metadata entries
func (l Logr) AddLootMetadataEntry(agentID string, metadata LootMetadata) error {
	return l.addLootMetadataEntry(agentID, metadata)
}

// addLootMetadataEntry is a helper function to add metadata entry
func (l Logr) addLootMetadataEntry(agentID string, metadata LootMetadata) error {
	var (
		agentPath = l.AgentPath + "/" + agentID
		indexPath = agentPath + "/loot_index.json"
	)

	// Create agent directory if it doesn't exist
	if _, err := os.Stat(agentPath); os.IsNotExist(err) {
		if err := os.Mkdir(agentPath, os.ModePerm); err != nil {
			return err
		}
	}

	// Load existing index or create new one
	var index LootIndex
	if data, err := ioutil.ReadFile(indexPath); err == nil {
		if err := json.Unmarshal(data, &index); err != nil {
			return err
		}
	} else {
		index = LootIndex{AgentID: agentID, Items: []LootMetadata{}}
	}

	index.Items = append(index.Items, metadata)

	// Save updated index
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(indexPath, data, 0644)
}

// GetLootIndex returns the loot index for an agent
func (l Logr) GetLootIndex(agentID string) (*LootIndex, error) {
	var (
		demonPath = l.AgentPath + "/" + agentID
		indexFile = demonPath + "/loot_index.json"
	)

	var lootIndex LootIndex
	data, err := ioutil.ReadFile(indexFile)
	if err != nil {
		// Return empty index if file doesn't exist
		return &LootIndex{AgentID: agentID, Items: []LootMetadata{}}, nil
	}

	err = json.Unmarshal(data, &lootIndex)
	if err != nil {
		return nil, err
	}

	return &lootIndex, nil
}

// GetAllLootIndices returns loot indices for all agents from the master index
func (l Logr) GetAllLootIndices() ([]LootIndex, error) {
	masterIndex, err := l.loadMasterLootIndex()
	if err != nil {
		logger.Error("Failed to load master loot index: " + err.Error())
		return []LootIndex{}, nil
	}

	// Group items by agent ID to maintain compatibility with existing client code
	agentMap := make(map[string][]LootMetadata)
	for _, item := range masterIndex.Items {
		agentMap[item.AgentID] = append(agentMap[item.AgentID], item)
	}

	// Convert to LootIndex format
	var indices []LootIndex
	for agentID, items := range agentMap {
		if len(items) > 0 {
			indices = append(indices, LootIndex{
				AgentID: agentID,
				Items:   items,
			})
		}
	}

	return indices, nil
}

// GetLootFile returns the content of a loot file using the master index
func (l Logr) GetLootFile(agentID, relativePath string) ([]byte, error) {
	logger.Debug(fmt.Sprintf("GetLootFile called with agentID: %s, relativePath: %s", agentID, relativePath))

	masterIndex, err := l.loadMasterLootIndex()
	if err != nil {
		logger.Error("GetLootFile: Failed to load master loot index: " + err.Error())
		return nil, errors.New("failed to load master loot index: " + err.Error())
	}

	logger.Debug(fmt.Sprintf("GetLootFile: Loaded master index with %d items", len(masterIndex.Items)))

	// Find the file in the master index
	for i, item := range masterIndex.Items {
		logger.Debug(fmt.Sprintf("GetLootFile: Checking item %d - AgentID: %s, RelativePath: %s, FullPath: %s", i, item.AgentID, item.RelativePath, item.FullPath))

		if item.AgentID == agentID && item.RelativePath == relativePath {
			logger.Debug(fmt.Sprintf("GetLootFile: Found matching item - FullPath: %s", item.FullPath))

			// Use the full path stored in the index
			data, err := ioutil.ReadFile(item.FullPath)
			if err != nil {
				logger.Error(fmt.Sprintf("GetLootFile: File found in index but could not read %s: %s", item.FullPath, err.Error()))
				return nil, errors.New("file found in index but could not read: " + err.Error())
			}
			logger.Debug(fmt.Sprintf("GetLootFile: Successfully read file %s (%d bytes)", item.FullPath, len(data)))
			return data, nil
		}
	}

	logger.Error(fmt.Sprintf("GetLootFile: File not found in master loot index - AgentID: %s, RelativePath: %s", agentID, relativePath))
	return nil, errors.New("file not found in master loot index: " + relativePath)
}

// getMasterLootIndexPath returns the path to the master loot index file
func (l Logr) getMasterLootIndexPath() string {
	baseLootDir := filepath.Dir(l.AgentPath)               // This gives us data/loot/2025.05.30._20:00:45
	parentLootDir := filepath.Dir(baseLootDir)             // This gives us data/loot
	return filepath.Join(parentLootDir, "loot_index.json") // This gives us data/loot/loot_index.json
}

// loadMasterLootIndex loads the master loot index from disk
func (l Logr) loadMasterLootIndex() (*MasterLootIndex, error) {
	indexPath := l.getMasterLootIndexPath()
	logger.Debug("Loading master loot index from: " + indexPath)

	var masterIndex MasterLootIndex
	data, err := ioutil.ReadFile(indexPath)
	if err != nil {
		// If file doesn't exist, return empty index
		if os.IsNotExist(err) {
			logger.Debug("Master loot index file does not exist: " + indexPath)
			return &MasterLootIndex{Items: []LootMetadata{}}, nil
		}
		logger.Error("Failed to read master loot index: " + err.Error())
		return nil, err
	}

	err = json.Unmarshal(data, &masterIndex)
	if err != nil {
		logger.Error("Failed to parse master loot index: " + err.Error())
		return nil, err
	}

	logger.Debug(fmt.Sprintf("Successfully loaded master loot index with %d items", len(masterIndex.Items)))
	return &masterIndex, nil
}

// saveMasterLootIndex saves the master loot index to disk
func (l Logr) saveMasterLootIndex(masterIndex *MasterLootIndex) error {
	indexPath := l.getMasterLootIndexPath()

	// Ensure the directory exists
	dir := filepath.Dir(indexPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return err
		}
	}

	data, err := json.MarshalIndent(masterIndex, "", "  ")
	if err != nil {
		return err
	}

	// Atomic write: write to temporary file first, then rename
	tempPath := indexPath + ".tmp"
	
	// Write to temporary file
	if err := ioutil.WriteFile(tempPath, data, 0644); err != nil {
		return err
	}
	
	// Atomic rename operation - this prevents corruption
	return os.Rename(tempPath, indexPath)
}

// addToMasterLootIndex adds a new loot item to the master index
func (l Logr) addToMasterLootIndex(metadata LootMetadata) error {
	masterIndex, err := l.loadMasterLootIndex()
	if err != nil {
		return err
	}

	masterIndex.Items = append(masterIndex.Items, metadata)
	return l.saveMasterLootIndex(masterIndex)
}

// AddToMasterLootIndex is a public wrapper for adding metadata to the master loot index
func (l Logr) AddToMasterLootIndex(metadata LootMetadata) error {
	return l.addToMasterLootIndex(metadata)
}

// DeleteLootFile removes a loot file from disk and from the master index
func (l Logr) DeleteLootFile(agentID, relativePath string) error {
	logger.Debug(fmt.Sprintf("DeleteLootFile called with agentID: %s, relativePath: %s", agentID, relativePath))

	masterIndex, err := l.loadMasterLootIndex()
	if err != nil {
		logger.Error("DeleteLootFile: Failed to load master loot index: " + err.Error())
		return errors.New("failed to load master loot index: " + err.Error())
	}

	logger.Debug(fmt.Sprintf("DeleteLootFile: Loaded master index with %d items", len(masterIndex.Items)))

	// Find the file in the master index and remove it
	var newItems []LootMetadata
	var fileToDelete string
	var found bool

	for _, item := range masterIndex.Items {
		if item.AgentID == agentID && item.RelativePath == relativePath {
			fileToDelete = item.FullPath
			found = true
			logger.Info(fmt.Sprintf("DeleteLootFile: Found file to delete - FullPath: %s", fileToDelete))
			// Don't append this item to newItems (effectively removing it)
		} else {
			newItems = append(newItems, item)
		}
	}

	if !found {
		logger.Error(fmt.Sprintf("DeleteLootFile: File not found in master loot index - AgentID: %s, RelativePath: %s", agentID, relativePath))
		return errors.New("file not found in master loot index: " + relativePath)
	}

	// Delete the physical file
	if err := os.Remove(fileToDelete); err != nil {
		logger.Error(fmt.Sprintf("DeleteLootFile: Failed to delete physical file %s: %s", fileToDelete, err.Error()))
		return errors.New("failed to delete physical file: " + err.Error())
	}

	logger.Info(fmt.Sprintf("DeleteLootFile: Successfully deleted physical file: %s", fileToDelete))

	// Update the master index with the file removed
	masterIndex.Items = newItems
	if err := l.saveMasterLootIndex(masterIndex); err != nil {
		logger.Error(fmt.Sprintf("DeleteLootFile: Failed to save updated master loot index: %s", err.Error()))
		return errors.New("failed to save updated master loot index: " + err.Error())
	}

	logger.Info(fmt.Sprintf("DeleteLootFile: Successfully removed file entry from master index. Remaining items: %d", len(newItems)))
	return nil
}
