package agent

import (
	"bytes"
	"encoding/binary"

	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"Havoc/pkg/common"
	"Havoc/pkg/common/crypt"
	"Havoc/pkg/common/packer"
	"Havoc/pkg/common/parser"
	"Havoc/pkg/logger"
	"Havoc/pkg/logr"

	"github.com/fatih/structs"
)

func BuildPayloadMessage(Jobs []Job, AesKey []byte, AesIv []byte) []byte {
	var (
		DataPayload        []byte
		PayloadPackage     []byte
		PayloadPackageSize = make([]byte, 4)
		RequestID          = make([]byte, 4)
		DataCommandID      = make([]byte, 4)
	)

	for _, job := range Jobs {

		for i := range job.Data {

			switch job.Data[i].(type) {
			case int:
				var integer32 = make([]byte, 4)

				binary.LittleEndian.PutUint32(integer32, uint32(job.Data[i].(int)))

				DataPayload = append(DataPayload, integer32...)

				break

			case int64:
				var integer64 = make([]byte, 8)

				binary.LittleEndian.PutUint64(integer64, uint64(job.Data[i].(int64)))

				DataPayload = append(DataPayload, integer64...)

				break

			case uint64:
				var integer64 = make([]byte, 8)

				binary.LittleEndian.PutUint64(integer64, uint64(job.Data[i].(uint64)))

				DataPayload = append(DataPayload, integer64...)

				break

			case int32:
				var integer32 = make([]byte, 4)

				binary.LittleEndian.PutUint32(integer32, uint32(job.Data[i].(int32)))

				DataPayload = append(DataPayload, integer32...)

				break

			case uint32:
				var integer32 = make([]byte, 4)

				binary.LittleEndian.PutUint32(integer32, job.Data[i].(uint32))

				DataPayload = append(DataPayload, integer32...)

				break

			case int16:
				var integer16 = make([]byte, 2)

				binary.LittleEndian.PutUint16(integer16, uint16(job.Data[i].(int16)))

				DataPayload = append(DataPayload, integer16...)

				break

			case uint16:
				var integer16 = make([]byte, 2)

				binary.LittleEndian.PutUint16(integer16, job.Data[i].(uint16))

				DataPayload = append(DataPayload, integer16...)

				break

			case string:
				var size = make([]byte, 4)

				str := job.Data[i].(string)

				// in C, strings terminate with a null-byte
				if strings.HasSuffix(str, "\x00") == false {
					str += "\x00"
				}

				binary.LittleEndian.PutUint32(size, uint32(len(str)))

				DataPayload = append(DataPayload, size...)
				DataPayload = append(DataPayload, []byte(str)...)

				break

			case []byte:
				var size = make([]byte, 4)

				binary.LittleEndian.PutUint32(size, uint32(len(job.Data[i].([]byte))))

				DataPayload = append(DataPayload, size...)
				DataPayload = append(DataPayload, job.Data[i].([]byte)...)

				break

			case byte:
				var singlebyte = make([]byte, 1)

				singlebyte[0] = job.Data[i].(byte)

				DataPayload = append(DataPayload, singlebyte...)

				break

			case bool:
				var boolean = make([]byte, 4)

				if job.Data[i].(bool) {
					binary.LittleEndian.PutUint32(boolean, 1)
				} else {
					binary.LittleEndian.PutUint32(boolean, 0)
				}

				DataPayload = append(DataPayload, boolean...)

				break

			default:
				logger.Error(fmt.Sprintf("Could not package, unknown data type: %v", job.Data[i]))
			}
		}

		binary.LittleEndian.PutUint32(DataCommandID, job.Command)
		PayloadPackage = append(PayloadPackage, DataCommandID...)

		binary.LittleEndian.PutUint32(RequestID, job.RequestID)
		PayloadPackage = append(PayloadPackage, RequestID...)

		binary.LittleEndian.PutUint32(PayloadPackageSize, uint32(len(DataPayload)))
		PayloadPackage = append(PayloadPackage, PayloadPackageSize...)

		if len(DataPayload) > 0 {
			DataPayload = crypt.XCryptBytesAES256(DataPayload, AesKey, AesIv)
			PayloadPackage = append(PayloadPackage, DataPayload...)
			DataPayload = nil
		}
	}

	//logger.Debug("PayloadPackage:\n", hex.Dump(PayloadPackage))

	return PayloadPackage
}

func ParseHeader(data []byte) (Header, error) {
	var (
		Header = Header{}
		Parser = parser.NewParser(data)
	)

	if Parser.Length() > 4 {
		Header.Size = Parser.ParseInt32()
	} else {
		return Header, errors.New("failed to parse package size")
	}

	if Parser.Length() > 4 {
		Header.MagicValue = Parser.ParseInt32()
	} else {
		return Header, errors.New("failed to parse magic value")
	}

	if Parser.Length() > 4 {
		Header.AgentID = Parser.ParseInt32()
	} else {
		return Header, errors.New("failed to parse agent id")
	}

	Header.Data = Parser

	logger.Debug(fmt.Sprintf("Header Size       : %d", Header.Size))
	logger.Debug(fmt.Sprintf("Header MagicValue : 0x%08x", Header.MagicValue))
	logger.Debug(fmt.Sprintf("Header AgentID    : %x", Header.AgentID))
	logger.Debug(fmt.Sprintf("Header Data       : \n%v", hex.Dump(Header.Data.Buffer())))

	return Header, nil
}

func RegisterInfoToInstance(Header Header, RegisterInfo map[string]any) *Agent {
	var (
		agent = &Agent{
			Active:     false,
			SessionDir: "",

			Info: new(AgentInfo),
		}
		err error
	)

	agent.NameID = fmt.Sprintf("%08x", Header.AgentID)
	agent.MagicValue = uint32(Header.MagicValue)

	// Magic Value Pool Debug Logging
	logger.Debug(fmt.Sprintf("Agent Registration - AgentID: %08x, MagicValue: 0x%08x", Header.AgentID, Header.MagicValue))
	if IsValidDemonMagic(uint32(Header.MagicValue)) {
		logger.Debug(fmt.Sprintf("Magic value 0x%08x is VALID (found in pool)", Header.MagicValue))
	} else {
		logger.Debug(fmt.Sprintf("Magic value 0x%08x is INVALID (not in pool)", Header.MagicValue))
	}

	if val, ok := RegisterInfo["Hostname"]; ok {
		agent.Info.Hostname = val.(string)
	}

	if val, ok := RegisterInfo["Username"]; ok {
		agent.Info.Username = val.(string)
	}

	if val, ok := RegisterInfo["Domain"]; ok {
		agent.Info.DomainName = val.(string)
	}

	if val, ok := RegisterInfo["InternalIP"]; ok {
		agent.Info.InternalIP = val.(string)
	}

	if val, ok := RegisterInfo["Process Path"]; ok {
		agent.Info.ProcessPath = val.(string)
	}

	if val, ok := RegisterInfo["Process Name"]; ok {
		agent.Info.ProcessName = val.(string)
	}

	if val, ok := RegisterInfo["Process Arch"]; ok {
		agent.Info.ProcessArch = val.(string)
	}

	if val, ok := RegisterInfo["Process ID"]; ok {
		agent.Info.ProcessPID, err = strconv.Atoi(val.(string))
		if err != nil {
			logger.DebugError("Couldn't parse ProcessID integer from string: " + err.Error())
			agent.Info.ProcessPID = 0
		}
	}

	if val, ok := RegisterInfo["Process Parent ID"]; ok {
		agent.Info.ProcessPPID, err = strconv.Atoi(val.(string))
		if err != nil {
			logger.DebugError("Couldn't parse ProcessPPID integer from string: " + err.Error())
			agent.Info.ProcessPPID = 0
		}
	}

	if val, ok := RegisterInfo["Process Elevated"]; ok {
		agent.Info.Elevated = "false"
		if val == "1" {
			agent.Info.Elevated = "true"
		}
	}

	// Updated OS Version handling
	if val, ok := RegisterInfo["OS Version"]; ok {
		// Assuming val is a string representing the OS version, split it by '.' to get the version parts
		versionParts := strings.Split(val.(string), ".")
		OsVersion := make([]int, len(versionParts))
		for i, part := range versionParts {
			OsVersion[i], _ = strconv.Atoi(part)
		}
		agent.Info.OSVersion = getWindowsVersionString(OsVersion)
	}

	if val, ok := RegisterInfo["OS Build"]; ok {
		agent.Info.OSBuild = val.(string)
	}

	if val, ok := RegisterInfo["OS Arch"]; ok {
		agent.Info.OSArch = val.(string)
	}

	if val, ok := RegisterInfo["SleepDelay"]; ok {
		switch v := val.(type) {
		case float64:
			agent.Info.SleepDelay = int(v)
		case string:
			agent.Info.SleepDelay, err = strconv.Atoi(v)
			if err != nil {
				logger.DebugError("Couldn't parse SleepDelay integer from string: " + err.Error())
				agent.Info.SleepDelay = 0
			}
		default:
			// handle unexpected type
			logger.DebugError("Unexpected type for SleepDelay: " + reflect.TypeOf(v).String())
			agent.Info.SleepDelay = 0
		}
	}

	agent.Info.FirstCallIn = time.Now().Format("02/01/2006 15:04:05")

	agent.Info.LastCallIn = time.Now().Format("02-01-2006 15:04:05")

	agent.BackgroundCheck = false
	agent.Active = true

	return agent
}

func ParseDemonRegisterRequest(AgentID int, Parser *parser.Parser, ExternalIP string) *Agent {
	//logger.Debug("Response:\n" + hex.Dump(Parser.Buffer()))

	var (
		MagicValue   int
		DemonID      int
		Hostname     string
		DomainName   string
		Username     string
		InternalIP   string
		ProcessName  string
		ProcessPID   int
		ProcessTID   int
		OsVersion    []int
		OsArch       int
		BaseAddress  int64
		Elevated     int
		ProcessArch  int
		ProcessPPID  int
		SleepDelay   int
		SleepJitter  int
		KillDate     int64
		WorkingHours int32
	)

	// NEW KEX FLOW:
	//   First packet: AgentHello (Ea || nonce_a || mac_a) - handled in handlers before reaching here.
	//   Second packet: metadata ONLY (no AES key/IV) encrypted with derived session keys.

	if Parser.Length() >= 4 {

		// The parser is already decrypted by handlers using session keys from KEX.
		var Session = &Agent{
			Active:     false,
			SessionDir: "",
			Info:       new(AgentInfo),
		}

		// CanIRead check: DemonID, ParentID, HopCount, Hostname, Username, Domain, InternalIP, ProcessName(UTF16), then many Int32s
		if Parser.CanIRead([]parser.ReadType{parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadBytes, parser.ReadBytes, parser.ReadBytes, parser.ReadBytes, parser.ReadBytes, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt64, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt32, parser.ReadInt64, parser.ReadInt32}) {
			DemonID = Parser.ParseInt32()
			logger.Debug(fmt.Sprintf("Parsed DemonID: %x", DemonID))

			if AgentID != DemonID {
				if AgentID != 0 {
					logger.Debug("Failed to decrypt agent init request")
					return nil
				}
			} else {
				logger.Debug(fmt.Sprintf("AgentID (%x) == DemonID (%x)\n", AgentID, DemonID))
			}

			// Pivot lineage
			ParentID := uint32(Parser.ParseInt32())
			HopCount := uint32(Parser.ParseInt32())

			Hostname = Parser.ParseString()
			Username = Parser.ParseString()
			DomainName = Parser.ParseString()
			InternalIP = Parser.ParseString()

			if ExternalIP != "" {
				Session.Info.ExternalIP = ExternalIP
			}

			logger.Debug(fmt.Sprintf(
				"\n"+
					"Hostname: %v\n"+
					"Username: %v\n"+
					"Domain  : %v\n"+
					"InternIP: %v\n"+
					"ExternIP: %v\n",
				Hostname, Username, DomainName, InternalIP, ExternalIP))

			ProcessName = Parser.ParseUTF16String()
			ProcessPID = Parser.ParseInt32()
			ProcessTID = Parser.ParseInt32()
			ProcessPPID = Parser.ParseInt32()
			ProcessArch = Parser.ParseInt32()
			Elevated = Parser.ParseInt32()
			BaseAddress = Parser.ParseInt64()

			logger.Debug(fmt.Sprintf(
				"\n"+
					"ProcessName : %v\n"+
					"ProcessPID  : %v\n"+
					"ProcessTID  : %v\n"+
					"ProcessPPID : %v\n"+
					"ProcessArch : %v\n"+
					"Elevated    : %v\n"+
					"Base Address: 0x%x\n",
				ProcessName, ProcessPID, ProcessTID, ProcessPPID, ProcessArch, Elevated, BaseAddress))

			OsVersion = []int{Parser.ParseInt32(), Parser.ParseInt32(), Parser.ParseInt32(), Parser.ParseInt32(), Parser.ParseInt32()}
			OsArch = Parser.ParseInt32()
			SleepDelay = Parser.ParseInt32()
			SleepJitter = Parser.ParseInt32()
			KillDate = Parser.ParseInt64()
			WorkingHours = int32(Parser.ParseInt32())

			logger.Debug(fmt.Sprintf(
				"\n"+
					"SleepDelay  : %v\n"+
					"SleepJitter : %v\n",
				SleepDelay, SleepJitter))

			Session.Active = true

			Session.NameID = fmt.Sprintf("%08x", DemonID)
			Session.MagicValue = uint32(MagicValue)

			// Generate dynamic commands for this session
			Session.DynamicCommands = GenerateDynamicCommands(uint32(DemonID))

			// Magic Value Debug for Demon Session
			logger.Debug(fmt.Sprintf("Demon Session - DemonID: %08x, MagicValue: 0x%08x", DemonID, MagicValue))
			if IsValidDemonMagic(uint32(MagicValue)) {
				logger.Debug(fmt.Sprintf("Session magic value 0x%08x is VALID (pool match)", MagicValue))
			} else {
				logger.Debug(fmt.Sprintf("Session magic value 0x%08x is INVALID (no pool match)", MagicValue))
			}
			Session.Info.FirstCallIn = time.Now().Format("02/01/2006 15:04:05")
			Session.Info.LastCallIn = time.Now().Format("02-01-2006 15:04:05")
			Session.Info.Hostname = Hostname
			Session.Info.DomainName = DomainName
			Session.Info.Username = Username
			Session.Info.InternalIP = InternalIP
			Session.Info.SleepDelay = SleepDelay
			Session.Info.SleepJitter = SleepJitter
			Session.Info.KillDate = KillDate
			Session.Info.WorkingHours = WorkingHours
			Session.Info.PivotParentID = ParentID
			Session.Info.PivotHopCount = HopCount

			// Listener type: set based on magic of transport; default to Http unless SMB flagged via parent ID/hop
			if ParentID != 0 || HopCount != 0 {
				Session.Info.Listener = "Smb"
			} else {
				Session.Info.Listener = "Http"
			}

			// Session.Info.Listener 	= t.Name

			switch ProcessArch {

			case PROCESS_ARCH_UNKNOWN:
				Session.Info.ProcessArch = "Unknown"
				break

			case PROCESS_ARCH_X64:
				Session.Info.ProcessArch = "x64"
				break

			case PROCESS_ARCH_X86:
				Session.Info.ProcessArch = "x86"
				break

			case PROCESS_ARCH_IA64:
				Session.Info.ProcessArch = "IA64"
				break

			default:
				Session.Info.ProcessArch = "Unknown"
				break

			}

			Session.Info.OSVersion = getWindowsVersionString(OsVersion)

			switch OsArch {
			case 0:
				Session.Info.OSArch = "x86"
			case 9:
				Session.Info.OSArch = "x64/AMD64"
			case 5:
				Session.Info.OSArch = "ARM"
			case 12:
				Session.Info.OSArch = "ARM64"
			case 6:
				Session.Info.OSArch = "Itanium-based"
			default:
				Session.Info.OSArch = "Unknown (" + strconv.Itoa(OsArch) + ")"
			}

			Session.Info.Elevated = "false"
			if Elevated == 1 {
				Session.Info.Elevated = "true"
			}

			process := strings.Split(ProcessName, "\\")

			Session.Info.ProcessName = process[len(process)-1]
			Session.Info.ProcessPID = ProcessPID
			Session.Info.ProcessTID = ProcessTID
			Session.Info.ProcessPPID = ProcessPPID
			Session.Info.ProcessPath = ProcessName
			Session.Info.BaseAddress = BaseAddress
			Session.BackgroundCheck = false

			/*for {
			    if Parser.Length() >= 4 {
			        var Option = Parser.ParseInt32()

			        switch Option {
			        case DEMON_CHECKIN_OPTION_PIVOTS:
			            logger.Debug("DEMON_CHECKIN_OPTION_PIVOTS")
			              var PivotCount = Parser.ParseInt32()

			              logger.Debug("PivotCount: ", PivotCount)

			              for {
			                  if PivotCount == 0 {
			                      break
			                  }

			                  var (
			                      PivotAgentID = Parser.ParseInt32()
			                      PivotPackage = Parser.ParseBytes()
			                      PivotParser  = parser.NewParser(PivotPackage)
			                      PivotSession *Agent
			                  )

			                  var (
			                      _             = PivotParser.ParseInt32()
			                      HdrMagicValue = PivotParser.ParseInt32()
			                      _             = PivotParser.ParseInt32()
			                      _             = PivotParser.ParseInt32()
			                  )

			                  PivotSession = ParseDemonRegisterRequest(PivotAgentID, PivotParser, RoutineFunc)
			                  if PivotSession != nil {
			                      PivotSession.Info.MagicValue = HdrMagicValue

			                      LogDemonCallback(PivotSession)
			                      RoutineFunc.AppendDemon(PivotSession)
			                      pk := RoutineFunc.EventNewDemon(PivotSession)
			                      RoutineFunc.EventAppend(pk)
			                      RoutineFunc.EventBroadcast("", pk)

			                      Session.Pivots.Links = append(Session.Pivots.Links, PivotSession)

			                      PivotSession.Pivots.Parent = Session
			                  }

			                  PivotCount--
			              }

			            break
			        }

			    } else {
			        break
			    }
			}*/

			logger.Debug("Finished parsing demon")

			return Session
		} else {
			logger.Debug(fmt.Sprintf("Agent: %x, Command: REGISTER, Invalid packet", AgentID))
			return nil
		}

	} else {
		logger.Debug(fmt.Sprintf("Agent: %x, Command: REGISTER, Invalid packet", AgentID))
		return nil
	}
}

// check that the request the agent is valid
func (a *Agent) IsKnownRequestID(teamserver TeamServer, RequestID uint32, CommandID uint32) bool {
	// some commands are always accepted because they don't follow the "send task and get response" format
	switch CommandID {
	case COMMAND_SOCKET:
		// **SECURITY FIX**: Enhanced validation in socket handler
		// Allow COMMAND_SOCKET to proceed but implement strict validation in the socket command parser
		return true
	case COMMAND_PIVOT:
		return true
	case COMMAND_INLINEEXECUTE:
		// **FIX**: BOF completion responses use agent-generated RequestIDs that don't match Task RequestIDs
		// BOF responses are validated through BofCallback matching instead
		return true
	}

	if teamserver.SendLogs() && CommandID == BEACON_OUTPUT {
		// if SendLogs is on, accept all BEACON_OUTPUT so that the agent can send logs
		return true
	}

	for i := range a.Tasks {
		if a.Tasks[i].RequestID == RequestID {
			return true
		}
	}
	return false
}

// the operator added a new request/command
func (a *Agent) AddRequest(job Job) []Job {
	a.Tasks = append(a.Tasks, job)
	return a.Tasks
}

// after a request has been completed, we can forget about the RequestID so that it is no longer valid
func (a *Agent) RequestCompleted(RequestID uint32) {
	for i := range a.Tasks {
		if a.Tasks[i].RequestID == RequestID {
			a.Tasks = append(a.Tasks[:i], a.Tasks[i+1:]...)
			break
		}
	}

	// NOTE: BofCallbacks are NOT cleaned up here.
	// They are consumed and removed by the RAN_OK / COULD_NO_RUN handlers
	// in demons.go after routing output to the Python module callback.
	// Cleaning them up here would destroy callbacks before those handlers
	// get a chance to use them (e.g. SYMBOL_NOT_FOUND -> COULD_NO_RUN flow).
}

func (a *Agent) AddJobToQueue(job Job) []Job {
	// store the RequestID
	a.AddRequest(job)
	// if it's a pivot agent then add the job to the parent
	if a.Pivots.Parent != nil {
		logger.Debug(fmt.Sprintf("Agent %s is pivot agent, adding job to parent %s", a.NameID, a.Pivots.Parent.NameID))
		a.PivotAddJob(job)
		// if it's a direct agent add the job to the direct agent
	} else {
		logger.Debug(fmt.Sprintf("Agent %s is direct agent, adding job to local queue", a.NameID))
		a.JobQueue = append(a.JobQueue, job)
	}
	return a.JobQueue
}

func (a *Agent) GetQueuedJobs() []Job {
	var Jobs []Job
	var JobsSize = 0
	var NumJobs = 0

	// make sure we return a number of jobs that doesn't exceed DEMON_MAX_RESPONSE_LENGTH
	for _, job := range a.JobQueue {

		for i := range job.Data {

			switch job.Data[i].(type) {
			case int:
				JobsSize += 4
				break

			case int64:
				JobsSize += 8
				break

			case uint64:
				JobsSize += 8
				break

			case int32:
				JobsSize += 4
				break

			case uint32:
				JobsSize += 4
				break

			case int16:
				JobsSize += 2
				break

			case uint16:
				JobsSize += 2
				break

			case string:
				JobsSize += 4 + len(job.Data[i].(string))
				break

			case []byte:
				JobsSize += 4 + len(job.Data[i].([]byte))
				break

			case byte:
				JobsSize += 1
				break

			case bool:
				JobsSize += 4
				break

			default:
				logger.Error(fmt.Sprintf("Could determine package size, unknown data type: %v", job.Data[i]))
			}
		}

		if JobsSize >= DEMON_MAX_RESPONSE_LENGTH {
			break
		}

		NumJobs++
	}

	// if there is a very large job, send it anyways
	if len(a.JobQueue) > 0 && NumJobs == 0 {
		NumJobs = 1
	}

	// return NumJobs and leave the rest on the JobQueue
	Jobs, a.JobQueue = a.JobQueue[:NumJobs], a.JobQueue[NumJobs:]

	return Jobs
}

func (a *Agent) UpdateLastCallback(Teamserver TeamServer) {
	a.Info.LastCallIn = time.Now().Format("02-01-2006 15:04:05")
	Teamserver.AgentUpdate(a)

	Teamserver.AgentLastTimeCalled(a.NameID, a.Info.LastCallIn, a.Info.SleepDelay, a.Info.SleepJitter, a.Info.KillDate, a.Info.WorkingHours)
}

// PivotAddRawFrame routes a pre-built raw frame to a pivot child through the parent chain.
// Unlike PivotAddJob, the innermost payload is NOT encrypted — used for KEX ServerHello
// where the target child doesn't have session keys yet. Intermediate hops ARE encrypted.
//
// Parameters:
//   - childAgent: the target child agent (must have Pivots.Parent set)
//   - rawFrame:   the pre-built frame bytes [AgentID_LE][PayloadLen_LE][ServerHello]
func PivotAddRawFrame(childAgent *Agent, rawFrame []byte) {
	var (
		pivots   *Pivots
		PivotJob Job
		AgentID  int64
		err      error
	)

	// Parse child's AgentID
	AgentID, err = strconv.ParseInt(childAgent.NameID, 16, 32)
	if err != nil {
		logger.Debug("PivotAddRawFrame: Failed to convert NameID: " + err.Error())
		return
	}

	// Innermost job: raw frame, NOT encrypted (child has no keys yet)
	PivotJob = Job{
		Command: COMMAND_PIVOT,
		Data: []interface{}{
			DEMON_PIVOT_SMB_COMMAND,
			int(AgentID),
			rawFrame,
		},
	}

	// Walk up the parent chain, wrapping with encryption at each hop
	pivots = &childAgent.Pivots

	for {
		if pivots.Parent == nil {
			logger.Error("PivotAddRawFrame: parent chain broken - no parent found")
			return
		}

		// If parent has no grandparent, parent is the HTTP root - queue here
		if pivots.Parent.Pivots.Parent == nil {
			break
		}

		// Intermediate hop: encrypt with this parent's keys and wrap
		Payload := BuildPayloadMessage([]Job{PivotJob}, pivots.Parent.Encryption.AESKey, pivots.Parent.Encryption.AESIv)
		Packer := packer.NewPacker(nil, nil)

		AgentID, err = strconv.ParseInt(pivots.Parent.NameID, 16, 32)
		if err != nil {
			logger.Debug("PivotAddRawFrame: Failed to convert parent NameID: " + err.Error())
			return
		}

		Packer.AddInt32(int32(AgentID))
		Packer.AddBytes(Payload)

		PivotJob = Job{
			Command: COMMAND_PIVOT,
			Data: []interface{}{
				DEMON_PIVOT_SMB_COMMAND,
				int(AgentID),
				Packer.Buffer(),
			},
		}

		pivots = &pivots.Parent.Pivots
	}

	// Queue on the HTTP root parent
	pivots.Parent.JobQueue = append(pivots.Parent.JobQueue, PivotJob)
	logger.Debug(fmt.Sprintf("PivotAddRawFrame: Queued raw frame for %s on HTTP root %s", childAgent.NameID, pivots.Parent.NameID))
}

func (a *Agent) PivotAddJob(job Job) {
	var (
		Payload  = BuildPayloadMessage([]Job{job}, a.Encryption.AESKey, a.Encryption.AESIv)
		Packer   = packer.NewPacker(nil, nil)
		pivots   *Pivots
		PivotJob Job
		AgentID  int64
		err      error
	)

	// core package that the end pivot receive
	AgentID, err = strconv.ParseInt(a.NameID, 16, 32)
	if err != nil {
		logger.Debug("Failed to convert NameID string to AgentID: " + err.Error())
		return
	}

	Packer.AddInt32(int32(AgentID))
	Packer.AddBytes(Payload)

	// add this job to pivot queue.
	// tho it's not going to be used besides for the task size calculator
	// which is going to be displayed to the operator.
	a.JobQueue = append(a.JobQueue, job)

	PivotJob = Job{
		Command: COMMAND_PIVOT,
		Data: []interface{}{
			DEMON_PIVOT_SMB_COMMAND,
			int(AgentID),
			Packer.Buffer(),
		},
	}

	pivots = &a.Pivots

	// pack it up for all the parent pivots.
	for {
		if pivots.Parent.Pivots.Parent == nil {
			break
		}

		// create new layer package.
		Payload = BuildPayloadMessage([]Job{PivotJob}, pivots.Parent.Encryption.AESKey, pivots.Parent.Encryption.AESIv)
		Packer = packer.NewPacker(nil, nil)

		AgentID, err = strconv.ParseInt(pivots.Parent.NameID, 16, 32)
		if err != nil {
			logger.Debug("Failed to convert NameID string to AgentID: " + err.Error())
			return
		}

		Packer.AddInt32(int32(AgentID))
		Packer.AddBytes(Payload)

		PivotJob = Job{
			Command: COMMAND_PIVOT,
			Data: []interface{}{
				DEMON_PIVOT_SMB_COMMAND,
				int(AgentID),
				Packer.Buffer(),
			},
		}

		pivots = &pivots.Parent.Pivots
	}

	pivots.Parent.JobQueue = append(pivots.Parent.JobQueue, PivotJob)
}

func (a *Agent) DownloadAdd(FileID int, FilePath string, FileSize int64, Aggressive bool) error {
	var (
		err      error
		download = &Download{
			FileID:     FileID,
			FilePath:   FilePath,
			TotalSize:  FileSize,
			Progress:   FileSize,
			State:      DOWNLOAD_STATE_RUNNING,
			Aggressive: Aggressive,
		}

		DemonPath        = logr.LogrInstance.AgentPath + "/" + a.NameID
		DemonDownloadDir = DemonPath + "/Download"
		DownloadFilePath = strings.Join(strings.Split(FilePath, "\\"), "/")
		FileSplit        = strings.Split(DownloadFilePath, "/")
		DownloadFile     = FileSplit[len(FileSplit)-1]
		DemonDownload    = DemonDownloadDir + "/" + strings.Join(FileSplit[:len(FileSplit)-1], "/")
	)

	/* check if we don't have a path traversal */
	path := filepath.Clean(DemonDownload)
	if !strings.HasPrefix(path, DemonDownloadDir) {
		logger.Error("File didn't started with agent download path. abort")
		return errors.New("File didn't started with agent download path. abort")
	}

	if _, err := os.Stat(DemonDownload); os.IsNotExist(err) {
		if err = os.MkdirAll(DemonDownload, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr demon download path" + a.NameID + ": " + err.Error())
			return errors.New("Failed to create Logr demon download path" + a.NameID + ": " + err.Error())
		}
	}

	/* remove null terminator. goland doesn't like it. */
	DownloadFile = common.StripNull(DownloadFile)

	download.File, err = os.Create(DemonDownload + "/" + DownloadFile)
	if err != nil {
		logger.Error("Failed to create file: " + err.Error())
		return errors.New("Failed to create file: " + err.Error())
	}

	download.LocalFile = DemonDownload + "/" + DownloadFile

	a.Downloads = append(a.Downloads, download)

	return nil
}

func (a *Agent) DownloadWrite(FileID int, data []byte) error {
	for i := range a.Downloads {
		if a.Downloads[i].FileID == FileID {
			_, err := a.Downloads[i].File.Write(data)
			if err != nil {
				a.Downloads[i].File, err = os.Create(a.Downloads[i].LocalFile)
				if err != nil {
					return errors.New("Failed to create file: " + err.Error())
				}

				_, err = a.Downloads[i].File.Write(data)
				if err != nil {
					return errors.New("Failed to write to file [" + a.Downloads[i].LocalFile + "]: " + err.Error())
				}

				a.Downloads[i].Progress += int64(len(data))
			}
			return nil
		}
	}
	return errors.New(fmt.Sprintf("FileID not found: %x", FileID))
}

func (a *Agent) DownloadClose(FileID int) {
	for i := range a.Downloads {
		if a.Downloads[i].FileID == FileID {
			err := a.Downloads[i].File.Close()
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to close download (%x) file: %v", a.Downloads[i].FileID, err))
			}

			a.Downloads = append(a.Downloads[:i], a.Downloads[i+1:]...)
			break
		}
	}
}

func (a *Agent) DownloadGet(FileID int) *Download {
	for _, download := range a.Downloads {
		if download.FileID == FileID {
			return download
		}
	}
	return nil
}

func (a *Agent) PortFwdNew(SocketID, LclAddr, LclPort, FwdAddr, FwdPort int, Target string) {
	var portfwd = &PortFwd{
		Conn:    nil,
		SocktID: SocketID,
		LclAddr: LclAddr,
		LclPort: LclPort,
		FwdAddr: FwdAddr,
		FwdPort: FwdPort,
		Target:  Target,
	}

	a.PortFwdsMtx.Lock()

	a.PortFwds = append(a.PortFwds, portfwd)

	a.PortFwdsMtx.Unlock()
}

func (a *Agent) PortFwdGet(SocketID int) *PortFwd {
	a.PortFwdsMtx.Lock()
	defer a.PortFwdsMtx.Unlock()

	for i := range a.PortFwds {

		/* check if it's our rportfwd connection */
		if a.PortFwds[i].SocktID == SocketID {

			/* return the found PortFwd object */
			return a.PortFwds[i]

		}

	}

	return nil
}

func (a *Agent) PortFwdIsOpen(SocketID int) (bool, error) {
	PortFwd := a.PortFwdGet(SocketID)

	if PortFwd != nil {
		return PortFwd.Conn != nil, nil
	} else {
		return false, fmt.Errorf("rportfwd socket id %x not found", SocketID)
	}
}

func (a *Agent) PortFwdOpen(SocketID int) error {
	var (
		err     error
		PortFwd *PortFwd
	)

	PortFwd = a.PortFwdGet(SocketID)

	if PortFwd != nil {
		if PortFwd.Conn == nil {
			/* open the connection to the target */
			PortFwd.Conn, err = net.Dial("tcp", PortFwd.Target)
			return err
		} else {
			return errors.New("rportfwd connection is already open")
		}
	} else {
		return fmt.Errorf("rportfwd socket id %x not found", SocketID)
	}
}

func (a *Agent) PortFwdWrite(SocketID int, data []byte) error {
	var PortFwd *PortFwd

	PortFwd = a.PortFwdGet(SocketID)

	if PortFwd != nil {
		/* write to the connection */
		if PortFwd.Conn != nil {
			_, err := PortFwd.Conn.Write(data)
			return err
		} else {
			return errors.New("rportfwd connection is empty")
		}
	} else {
		return fmt.Errorf("rportfwd socket id %x not found", SocketID)
	}
}

func (a *Agent) PortFwdRead(SocketID int) ([]byte, error) {
	var (
		data    = bytes.Buffer{}
		PortFwd *PortFwd
	)

	PortFwd = a.PortFwdGet(SocketID)

	if PortFwd != nil {
		if PortFwd.Conn != nil {
			/* read from our socket to the data buffer or return error */
			_, err := io.Copy(&data, PortFwd.Conn)
			if err != nil {
				return nil, err
			}

			/* return the read data */
			return data.Bytes(), nil
		} else {
			return nil, errors.New("rportfwd connection is empty")
		}
	} else {
		return nil, fmt.Errorf("rportfwd socket id %x not found", SocketID)
	}
}

func (a *Agent) PortFwdClose(SocketID int) {
	a.PortFwdsMtx.Lock()
	defer a.PortFwdsMtx.Unlock()

	for i := range a.PortFwds {

		/* check if it's our rportfwd connection */
		if a.PortFwds[i].SocktID == SocketID {

			/* is there a socket? if not the not try anything or else we get an exception */
			if a.PortFwds[i].Conn != nil {

				logger.Info("Portfwd close")

				/* close our connection */
				a.PortFwds[i].Conn.Close()
				a.PortFwds[i].Conn = nil

			}

			/* remove the socket from the array */
			a.PortFwds = append(a.PortFwds[:i], a.PortFwds[i+1:]...)

			break
		}

	}

}

func (a *Agent) SocksClientAdd(SocketID int32, conn net.Conn, ATYP byte, IpDomain []byte, Port uint16) *SocksClient {

	var client = new(SocksClient)

	client.SocketID = SocketID
	client.Conn = conn
	client.Connected = false
	client.ATYP = ATYP
	client.IpDomain = IpDomain
	client.Port = Port

	a.SocksCliMtx.Lock()

	a.SocksCli = append(a.SocksCli, client)

	a.SocksCliMtx.Unlock()

	return client
}

func (a *Agent) SocksClientGet(SocketID int) *SocksClient {
	var (
		client *SocksClient = nil
	)

	a.SocksCliMtx.Lock()

	for i := range a.SocksCli {

		if a.SocksCli[i].SocketID == int32(SocketID) {

			client = a.SocksCli[i]

			break
		}

	}

	a.SocksCliMtx.Unlock()

	return client
}

func (a *Agent) SocksClientRead(client *SocksClient) ([]byte, error) {
	var (
		data = make([]byte, 0x10000)
		read []byte
	)

	if client != nil {
		if client.Conn != nil {
			if client.Connected {

				/* read from our socket to the data buffer or return error */
				client.Conn.SetReadDeadline(time.Time{})
				length, err := client.Conn.Read(data)
				if err != nil {
					return nil, err
				}

				read = make([]byte, length)
				copy(read, data)

				/* return the read data */
				return read, nil

			} else {
				return nil, errors.New("socks proxy is not connected")
			}
		} else {
			return nil, errors.New("socks proxy connection is empty")
		}
	} else {
		return nil, errors.New("socks proxy empty client")
	}
}

func (a *Agent) SocksClientClose(SocketID int32) bool {
	found := false

	a.SocksCliMtx.Lock()

	for i := range a.SocksCli {

		/* check if it's our rportfwd connection */
		if a.SocksCli[i].SocketID == int32(SocketID) {

			/* is there a socket? if not the not try anything or else we get an exception */
			if a.SocksCli[i].Conn != nil {

				/* close our connection */
				a.SocksCli[i].Conn.Close()
				a.SocksCli[i].Conn = nil

			}

			/* remove the socks server from the array */
			a.SocksCli = append(a.SocksCli[:i], a.SocksCli[i+1:]...)

			found = true

			break
		}
	}

	a.SocksCliMtx.Unlock()

	return found
}

func (a *Agent) SocksServerRemove(Addr string) {

	a.SocksSvrMtx.Lock()

	for i := range a.SocksSvr {

		if a.SocksSvr[i].Addr == Addr {

			/* is there a socket? if not the not try anything or else we get an exception */
			if a.SocksSvr[i].Server != nil {

				/* close our connection */
				a.SocksSvr[i].Server.Close()
				a.SocksSvr[i].Server = nil

			}

			/* remove the socket from the array */
			a.SocksSvr = append(a.SocksSvr[:i], a.SocksSvr[i+1:]...)

			break
		}

	}

	a.SocksSvrMtx.Unlock()

}

// AuthorizeSocketOperation adds a socket operation to the authorized list
func (a *Agent) AuthorizeSocketOperation(taskID uint32, socketID int32, opType string) {
	a.AuthorizedSocketOpsMtx.Lock()
	defer a.AuthorizedSocketOpsMtx.Unlock()

	authOp := &AuthorizedSocketOp{
		TaskID:     taskID,
		SocketID:   socketID,
		OpType:     opType,
		Authorized: true,
		CreatedAt:  time.Now(),
	}

	a.AuthorizedSocketOps = append(a.AuthorizedSocketOps, authOp)
}

// IsSocketOperationAuthorized checks if a socket operation is authorized for a task
func (a *Agent) IsSocketOperationAuthorized(taskID uint32, socketID int32) bool {
	a.AuthorizedSocketOpsMtx.Lock()
	defer a.AuthorizedSocketOpsMtx.Unlock()

	for _, authOp := range a.AuthorizedSocketOps {
		if authOp.TaskID == taskID && authOp.SocketID == socketID && authOp.Authorized {
			return true
		}
	}
	return false
}

// IsSocketIDAuthorized checks if a socket ID has any authorized operations (for callback validation)
func (a *Agent) IsSocketIDAuthorized(socketID int32) bool {
	a.AuthorizedSocketOpsMtx.Lock()
	defer a.AuthorizedSocketOpsMtx.Unlock()

	for _, authOp := range a.AuthorizedSocketOps {
		if authOp.SocketID == socketID && authOp.Authorized {
			return true
		}
	}
	return false
}

// RevokeSocketAuthorization removes authorization for a socket operation
func (a *Agent) RevokeSocketAuthorization(socketID int32) {
	a.AuthorizedSocketOpsMtx.Lock()
	defer a.AuthorizedSocketOpsMtx.Unlock()

	for i, authOp := range a.AuthorizedSocketOps {
		if authOp.SocketID == socketID {
			a.AuthorizedSocketOps = append(a.AuthorizedSocketOps[:i], a.AuthorizedSocketOps[i+1:]...)
			break
		}
	}
}

// CleanupExpiredSocketAuthorizations removes old socket authorizations (older than 24 hours)
func (a *Agent) CleanupExpiredSocketAuthorizations() {
	a.AuthorizedSocketOpsMtx.Lock()
	defer a.AuthorizedSocketOpsMtx.Unlock()

	cutoffTime := time.Now().Add(-24 * time.Hour)
	validOps := make([]*AuthorizedSocketOp, 0)

	for _, authOp := range a.AuthorizedSocketOps {
		if authOp.CreatedAt.After(cutoffTime) {
			validOps = append(validOps, authOp)
		}
	}

	a.AuthorizedSocketOps = validOps
}

// validateSocketOperation validates if a socket operation is legitimate
func (a *Agent) validateSocketOperation(requestID uint32, teamserver TeamServer) bool {
	// Method 1: Check if this is a legitimate task response
	for i := range a.Tasks {
		if a.Tasks[i].RequestID == requestID && a.Tasks[i].Command == COMMAND_SOCKET {
			logger.Debug(fmt.Sprintf("COMMAND_SOCKET RequestID %d validated against legitimate task", requestID))
			return true
		}
	}

	// Method 2: Check if this is a callback from an active socket operation
	// This is needed for operations like data transfer in rportfwd and socks
	// that generate new callbacks with agent-generated RequestIDs

	// Check if we have any active port forwards - these can generate callbacks
	a.PortFwdsMtx.Lock()
	hasActivePortFwd := len(a.PortFwds) > 0
	a.PortFwdsMtx.Unlock()

	// Check if we have any active socks clients - these can generate callbacks
	a.SocksCliMtx.Lock()
	hasActiveSocks := len(a.SocksCli) > 0
	a.SocksCliMtx.Unlock()

	// Check if we have any active socks servers - these can generate callbacks
	a.SocksSvrMtx.Lock()
	hasActiveSocksServer := len(a.SocksSvr) > 0
	a.SocksSvrMtx.Unlock()

	if hasActivePortFwd || hasActiveSocks || hasActiveSocksServer {
		logger.Debug(fmt.Sprintf("COMMAND_SOCKET RequestID %d allowed due to active socket operations", requestID))
		return true
	}

	// Method 3: Reject unknown socket operations
	logger.Error(fmt.Sprintf("COMMAND_SOCKET RequestID %d rejected - no matching task or active socket operations", requestID))
	return false
}

// isValidPortForwardTarget validates that a port forward target is legitimate
// This prevents arbitrary SSRF connections while allowing legitimate rportfwd operations
func (a *Agent) isValidPortForwardTarget(lclAddr, lclPort, fwdAddr, fwdPort int) bool {
	// For SOCKET_COMMAND_OPEN, we should only allow connections that correspond to
	// legitimate rportfwd configurations that were set up via proper tasks.

	// This is a very restrictive approach - only allow if we have active rportfwd tasks
	// Check if there are any rportfwd tasks in our task queue that could have initiated this
	hasRportfwdTask := false
	for i := range a.Tasks {
		if a.Tasks[i].Command == COMMAND_SOCKET {
			// Check if this task contains rportfwd data
			// a.Tasks[i].Data is already []interface{}, no need to type assert
			if len(a.Tasks[i].Data) > 0 {
				if subCmd, ok := a.Tasks[i].Data[0].(int); ok {
					if subCmd == SOCKET_COMMAND_RPORTFWD_ADD {
						hasRportfwdTask = true
						break
					}
				}
			}
		}
	}

	if !hasRportfwdTask {
		logger.Error(fmt.Sprintf("SOCKET_COMMAND_OPEN blocked: no legitimate rportfwd task found"))
		return false
	}

	// Additional security checks:
	// 1. Block localhost/loopback connections unless explicitly allowed
	lclAddrStr := common.Int32ToIpString(int64(lclAddr))
	fwdAddrStr := common.Int32ToIpString(int64(fwdAddr))

	// Block connections to localhost/127.0.0.1 unless both ends are localhost (legitimate local forwarding)
	if strings.HasPrefix(fwdAddrStr, "127.") || fwdAddrStr == "localhost" {
		if !strings.HasPrefix(lclAddrStr, "127.") && lclAddrStr != "localhost" {
			logger.Error(fmt.Sprintf("SOCKET_COMMAND_OPEN blocked: attempted connection to localhost %s from non-localhost %s", fwdAddrStr, lclAddrStr))
			return false
		}
	}

	// Block common internal IP ranges that could be used for SSRF
	// This is a basic check - could be enhanced with more comprehensive IP validation
	if strings.HasPrefix(fwdAddrStr, "10.") ||
		strings.HasPrefix(fwdAddrStr, "192.168.") ||
		strings.HasPrefix(fwdAddrStr, "172.") {
		logger.Warn(fmt.Sprintf("SOCKET_COMMAND_OPEN to internal IP %s - verify this is legitimate", fwdAddrStr))
	}

	// Block privileged ports (< 1024) unless explicitly allowed
	if fwdPort < 1024 {
		logger.Warn(fmt.Sprintf("SOCKET_COMMAND_OPEN to privileged port %d - verify this is legitimate", fwdPort))
	}

	logger.Debug(fmt.Sprintf("SOCKET_COMMAND_OPEN validated: %s:%d -> %s:%d", lclAddrStr, lclPort, fwdAddrStr, fwdPort))
	return true
}

// ToMap returns the agent info as a map
func (a *Agent) ToMap() map[string]interface{} {
	var (
		ParentAgent *Agent
		Info        map[string]any
		MagicValue  string
	)

	ParentAgent = a.Pivots.Parent
	a.Pivots.Parent = nil

	Info = structs.Map(a)

	Info["Info"].(map[string]interface{})["Listener"] = nil

	delete(Info, "Connection")
	delete(Info, "SessionDir")
	delete(Info, "JobQueue")
	delete(Info, "Parent")

	MagicValue = fmt.Sprintf("%08x", a.MagicValue)

	if ParentAgent != nil {
		Info["PivotParent"] = ParentAgent.NameID
		a.Pivots.Parent = ParentAgent
	}

	Info["MagicValue"] = MagicValue

	return Info
}

func (a *Agent) ToJson() string {
	// TODO: add Agents pivot links too

	jsonBytes, err := json.Marshal(a.ToMap())
	if err != nil {
		logger.Error("Failed to marshal object to json: " + err.Error())
		return ""
	}

	logger.Debug("jsonBytes =>", string(jsonBytes))

	return string(jsonBytes)
}

func (agents *Agents) AgentsAppend(demon *Agent) []*Agent {
	agents.Agents = append(agents.Agents, demon)
	return agents.Agents
}

func getWindowsVersionString(OsVersion []int) string {
	var WinVersion = "Unknown"

	if OsVersion[0] == 10 && OsVersion[1] == 0 && OsVersion[2] != 0x0000001 && OsVersion[4] == 20348 {
		WinVersion = "Windows 2022 Server 22H2"
	} else if OsVersion[0] == 10 && OsVersion[1] == 0 && OsVersion[2] != 0x0000001 && OsVersion[4] == 17763 {
		WinVersion = "Windows 2019 Server"
	} else if OsVersion[0] == 10 && OsVersion[1] == 0 && OsVersion[2] == 0x0000001 && (OsVersion[4] >= 22000 && OsVersion[4] <= 22621) {
		WinVersion = "Windows 11"
	} else if OsVersion[0] == 10 && OsVersion[1] == 0 && OsVersion[2] != 0x0000001 {
		WinVersion = "Windows 2016 Server"
	} else if OsVersion[0] == 10 && OsVersion[1] == 0 && OsVersion[2] == 0x0000001 {
		WinVersion = "Windows 10"
	} else if OsVersion[0] == 6 && OsVersion[1] == 3 && OsVersion[2] != 0x0000001 {
		WinVersion = "Windows Server 2012 R2"
	} else if OsVersion[0] == 6 && OsVersion[1] == 3 && OsVersion[2] == 0x0000001 {
		WinVersion = "Windows 8.1"
	} else if OsVersion[0] == 6 && OsVersion[1] == 2 && OsVersion[2] != 0x0000001 {
		WinVersion = "Windows Server 2012"
	} else if OsVersion[0] == 6 && OsVersion[1] == 2 && OsVersion[2] == 0x0000001 {
		WinVersion = "Windows 8"
	} else if OsVersion[0] == 6 && OsVersion[1] == 1 && OsVersion[2] != 0x0000001 {
		WinVersion = "Windows Server 2008 R2"
	} else if OsVersion[0] == 6 && OsVersion[1] == 1 && OsVersion[2] == 0x0000001 {
		WinVersion = "Windows 7"
	}

	if OsVersion[3] != 0 {
		WinVersion += " Service Pack " + strconv.Itoa(OsVersion[3])
	}

	return WinVersion
}
