package server

import (
	"Havoc/pkg/agent"
	"Havoc/pkg/logger"
	"fmt"
)

func (t *Teamserver) ServiceAgent(MagicValue int) agent.ServiceAgentInterface {
	// **SECURITY FIX**: Check if Service is nil before accessing it
	if t.Service == nil {
		logger.Debug("Service is not configured")
		return nil
	}

	for _, agentService := range t.Service.Agents {
		if agentService.MagicValue == fmt.Sprintf("0x%x", MagicValue) {
			return agentService
		}
	}

	logger.Debug("Service agent not found")
	return nil
}

func (t *Teamserver) ServiceAgentExist(MagicValue int) bool {
	// **SECURITY FIX**: Check if Service is nil before accessing it
	if t.Service == nil {
		logger.Debug("Service is not configured")
		return false
	}

	for _, agentService := range t.Service.Agents {
		if agentService.MagicValue == fmt.Sprintf("0x%x", MagicValue) {
			return true
		}
	}

	logger.Debug("Service agent not found")
	return false
}
