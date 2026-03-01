package handlers

import (
    "Havoc/pkg/colors"
    "Havoc/pkg/logger"
)

func NewPivotSmb() *SMB {
    var Smb = new(SMB)

    return Smb
}

func (s *SMB) Start() {
    logger.Info("Started \"" + colors.Green(s.Config.Name) + "\" listener")

    pk := s.Teamserver.ListenerAdd("", LISTENER_PIVOT_SMB, s)
    s.Teamserver.EventAppend(pk)
    s.Teamserver.EventBroadcast("", pk)
}

// HandlePivotPacket processes SMB pivot data using the same logic as HTTP handler
// This assumes the caller reads from the named pipe and passes the raw packet bytes.
func (s *SMB) HandlePivotPacket(body []byte) ([]byte, bool) {
	// Use a synthetic ExternalIP for pivots
	resp, ok := parseAgentRequest(s.Teamserver, body, "", []byte(s.Config.PSK))
	if !ok {
		return nil, false
	}
	return resp.Bytes(), true
}
