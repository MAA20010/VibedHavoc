package agent

import (
	"fmt"
	"Havoc/pkg/logger"
)

// Magic value pool
// This pool must match the C/C++ implementation exactly
var DEMON_MAGIC_POOL = [32]uint32{
	0xACCB32ED, 0x8F7E4C21, 0x3A9B5D82, 0xE2F1C067,
	0x7B8A9F3E, 0x4D6E2A95, 0x9C8F7B12, 0x5E3A8D47,
	0xA1B2C3D4, 0xF8E7D6C5, 0x2E4F6A8B, 0x9D5C3B1A,
	0x6A7B8C9D, 0x1F2E3D4C, 0x8B9A7C6D, 0x4E5F6A7B,
	0xC3D4E5F6, 0x7A8B9C1D, 0x5E6F7A8B, 0x2D3E4F5A,
	0x9C1B2A3D, 0x6E7F8A9B, 0x3B4C5D6E, 0x8A9B1C2D,
	0x5F6A7B8C, 0x2A3B4C5D, 0x7E8F9A1B, 0x4C5D6E7F,
	0x1A2B3C4D, 0x8E9F1A2B, 0x5C6D7E8F, 0x3F4A5B6C,
}

// Dynamic command pools
var DYNAMIC_COMMAND_POOLS = map[string][32]uint32{
	"BASE_COMMANDS": {
		0x8A7F3E91, 0x4D2B8C67, 0x9F5A1D82, 0xE3C6B094,
		0x7B4E9A25, 0x5D8F2C19, 0xA6E3F748, 0x2C9B7E53,
		0xF1D4A829, 0x6E8B3C47, 0x5A9E7F12, 0x3C6D8B94,
		0x8F2A5E73, 0x7C4B9D81, 0x6A3F8E92, 0x9B7C4A65,
		0x4E8D6F23, 0x7A5C9B84, 0x3F6E8A71, 0x8C5D7B49,
		0x6F9A4E82, 0x5B8C7D93, 0x4A7E9F65, 0x8D6C3B74,
		0x7E9B5A81, 0x3C8F6D42, 0x9A7B4E63, 0x6D8C5F94,
		0x4B7A9E85, 0x8F6D3C72, 0x5E9A7B41, 0x7C4F8D96,
	},
	"SUB_COMMANDS": {
		0x1A2B3C4D, 0x5E6F7A8B, 0x9C1D2E3F, 0x4A5B6C7D,
		0x8E9F1A2B, 0x5C6D7E8F, 0x3F4A5B6C, 0x7E8F9A1B,
		0x2C3D4E5F, 0x6A7B8C9D, 0x1E2F3A4B, 0x5C6D7E8F,
		0x9A1B2C3D, 0x6E7F8A9B, 0x4A5B6C7D, 0x8E9F1A2B,
		0x3C4D5E6F, 0x7A8B9C1D, 0x2E3F4A5B, 0x6C7D8E9F,
		0x1A2B3C4D, 0x7E8F9A1B, 0x5B6C7D8E, 0x9F1A2B3C,
		0x4D5E6F7A, 0x8B9C1D2E, 0x3F4A5B6C, 0x7D8E9F1A,
		0x2B3C4D5E, 0x9A1B2C3D, 0x6E7F8A9B, 0x4A5B6C7D,
	},
}

// Debug function to log magic pool status
func LogMagicPoolStatus() {
	logger.Debug("=== MAGIC VALUE POOL DEBUG STATUS ===")
	logger.Debug(fmt.Sprintf("Pool Size: %d values", len(DEMON_MAGIC_POOL)))
	for i, magic := range DEMON_MAGIC_POOL {
		logger.Debug(fmt.Sprintf("Pool[%02d]: 0x%08X", i, magic))
	}
	logger.Debug("======================================")
}

// Legacy magic value for backward compatibility
const (
	DEMON_MAGIC_VALUE = 0xACCB32ED
)

// IsValidDemonMagic checks if the provided magic value is in our accepted pool
func IsValidDemonMagic(magic uint32) bool {
	for _, validMagic := range DEMON_MAGIC_POOL {
		if magic == validMagic {
			return true
		}
	}
	return false
}

// GenerateDynamicCommands creates session-specific command mapping
func GenerateDynamicCommands(agentID uint32) *DynamicCommandMap {
	// Create deterministic seed from AgentID and compile-time constant
	seed := agentID ^ 0x76543210 // Fixed seed for deterministic results
	
	basePool := DYNAMIC_COMMAND_POOLS["BASE_COMMANDS"]
	
	commands := &DynamicCommandMap{
		// Main Commands (22 total) - ONLY these flow through agent's DemonCommands[] dispatcher
		Sleep:                     basePool[(seed+0)%32],   // DEMON_COMMAND_SLEEP
		Checkin:                   basePool[(seed+1)%32],   // DEMON_COMMAND_CHECKIN
		Job:                       basePool[(seed+2)%32],   // DEMON_COMMAND_JOB
		Proc:                      basePool[(seed+3)%32],   // DEMON_COMMAND_PROC (unused but in table)
		ProcList:                  basePool[(seed+4)%32],   // DEMON_COMMAND_PROC_LIST
		FS:                        basePool[(seed+5)%32],   // DEMON_COMMAND_FS
		InlineExecute:             basePool[(seed+6)%32],   // DEMON_COMMAND_INLINE_EXECUTE
		AssemblyInlineExecute:     basePool[(seed+7)%32],   // DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE
		AssemblyVersions:          basePool[(seed+8)%32],   // DEMON_COMMAND_ASSEMBLY_VERSIONS
		Config:                    basePool[(seed+9)%32],   // DEMON_COMMAND_CONFIG
		Screenshot:                basePool[(seed+10)%32],  // DEMON_COMMAND_SCREENSHOT
		Pivot:                     basePool[(seed+11)%32],  // DEMON_COMMAND_PIVOT
		Net:                       basePool[(seed+12)%32],  // DEMON_COMMAND_NET
		InjectDLL:                 basePool[(seed+13)%32],  // DEMON_COMMAND_INJECT_DLL
		InjectShellcode:           basePool[(seed+14)%32],  // DEMON_COMMAND_INJECT_SHELLCODE
		SpawnDLL:                  basePool[(seed+15)%32],  // DEMON_COMMAND_SPAWN_DLL
		Token:                     basePool[(seed+16)%32],  // DEMON_COMMAND_TOKEN
		Transfer:                  basePool[(seed+17)%32],  // DEMON_COMMAND_TRANSFER
		Socket:                    basePool[(seed+18)%32],  // DEMON_COMMAND_SOCKET
		Kerberos:                  basePool[(seed+19)%32],  // DEMON_COMMAND_KERBEROS
		MemFile:                   basePool[(seed+20)%32],  // DEMON_COMMAND_MEM_FILE
		Exit:                      basePool[(seed+21)%32],  // DEMON_EXIT
	}
	
	logger.Debug(fmt.Sprintf("Generated dynamic command mapping for agent %08x (22 main commands):", agentID))
	logger.Debug(fmt.Sprintf("  Sleep: 0x%08x (static: %d) %s", commands.Sleep, COMMAND_SLEEP, validateDynamic(commands.Sleep, COMMAND_SLEEP)))
	logger.Debug(fmt.Sprintf("  Checkin: 0x%08x (static: %d) %s", commands.Checkin, COMMAND_CHECKIN, validateDynamic(commands.Checkin, COMMAND_CHECKIN)))
	logger.Debug(fmt.Sprintf("  Job: 0x%08x (static: %d) %s", commands.Job, COMMAND_JOB, validateDynamic(commands.Job, COMMAND_JOB)))
	logger.Debug(fmt.Sprintf("  Proc: 0x%08x (static: %d) %s", commands.Proc, COMMAND_PROC, validateDynamic(commands.Proc, COMMAND_PROC)))
	logger.Debug(fmt.Sprintf("  ProcList: 0x%08x (static: %d) %s", commands.ProcList, COMMAND_PROC_LIST, validateDynamic(commands.ProcList, COMMAND_PROC_LIST)))
	logger.Debug(fmt.Sprintf("  FS: 0x%08x (static: %d) %s", commands.FS, COMMAND_FS, validateDynamic(commands.FS, COMMAND_FS)))
	logger.Debug(fmt.Sprintf("  InlineExecute: 0x%08x (static: %d) %s", commands.InlineExecute, COMMAND_INLINEEXECUTE, validateDynamic(commands.InlineExecute, COMMAND_INLINEEXECUTE)))
	logger.Debug(fmt.Sprintf("  AssemblyInlineExecute: 0x%08x (static: %d) %s", commands.AssemblyInlineExecute, COMMAND_ASSEMBLY_INLINE_EXECUTE, validateDynamic(commands.AssemblyInlineExecute, COMMAND_ASSEMBLY_INLINE_EXECUTE)))
	logger.Debug(fmt.Sprintf("  AssemblyVersions: 0x%08x (static: %d) %s", commands.AssemblyVersions, COMMAND_ASSEMBLY_VERSIONS, validateDynamic(commands.AssemblyVersions, COMMAND_ASSEMBLY_VERSIONS)))
	logger.Debug(fmt.Sprintf("  Config: 0x%08x (static: %d) %s", commands.Config, COMMAND_CONFIG, validateDynamic(commands.Config, COMMAND_CONFIG)))
	logger.Debug(fmt.Sprintf("  Screenshot: 0x%08x (static: %d) %s", commands.Screenshot, COMMAND_SCREENSHOT, validateDynamic(commands.Screenshot, COMMAND_SCREENSHOT)))
	logger.Debug(fmt.Sprintf("  Pivot: 0x%08x (static: %d) %s", commands.Pivot, COMMAND_PIVOT, validateDynamic(commands.Pivot, COMMAND_PIVOT)))
	logger.Debug(fmt.Sprintf("  Net: 0x%08x (static: %d) %s", commands.Net, COMMAND_NET, validateDynamic(commands.Net, COMMAND_NET)))
	logger.Debug(fmt.Sprintf("  InjectDLL: 0x%08x (static: %d) %s", commands.InjectDLL, COMMAND_INJECT_DLL, validateDynamic(commands.InjectDLL, COMMAND_INJECT_DLL)))
	logger.Debug(fmt.Sprintf("  InjectShellcode: 0x%08x (static: %d) %s", commands.InjectShellcode, COMMAND_INJECT_SHELLCODE, validateDynamic(commands.InjectShellcode, COMMAND_INJECT_SHELLCODE)))
	logger.Debug(fmt.Sprintf("  SpawnDLL: 0x%08x (static: %d) %s", commands.SpawnDLL, COMMAND_SPAWN_DLL, validateDynamic(commands.SpawnDLL, COMMAND_SPAWN_DLL)))
	logger.Debug(fmt.Sprintf("  Token: 0x%08x (static: %d) %s", commands.Token, COMMAND_TOKEN, validateDynamic(commands.Token, COMMAND_TOKEN)))
	logger.Debug(fmt.Sprintf("  Transfer: 0x%08x (static: %d) %s", commands.Transfer, COMMAND_TRANSFER, validateDynamic(commands.Transfer, COMMAND_TRANSFER)))
	logger.Debug(fmt.Sprintf("  Socket: 0x%08x (static: %d) %s", commands.Socket, COMMAND_SOCKET, validateDynamic(commands.Socket, COMMAND_SOCKET)))
	logger.Debug(fmt.Sprintf("  Kerberos: 0x%08x (static: %d) %s", commands.Kerberos, COMMAND_KERBEROS, validateDynamic(commands.Kerberos, COMMAND_KERBEROS)))
	logger.Debug(fmt.Sprintf("  MemFile: 0x%08x (static: %d) %s", commands.MemFile, COMMAND_MEM_FILE, validateDynamic(commands.MemFile, COMMAND_MEM_FILE)))
	logger.Debug(fmt.Sprintf("  Exit: 0x%08x (static: %d) %s", commands.Exit, DEMON_EXIT, validateDynamic(commands.Exit, DEMON_EXIT)))
	logger.Debug(fmt.Sprintf("TOTAL: 22 main commands (matches agent DemonCommands[] table)"))
	
	return commands
}

// validateDynamic ensures dynamic values differ from static ones
func validateDynamic(dynamic uint32, static uint32) string {
	if dynamic == static {
		return "⚠️  STATIC VALUE DETECTED!"
	}
	return "✅ DYNAMIC"
}

// ResolveDynamicCommand attempts to resolve a command using dynamic mapping
// Falls back to static commands for backward compatibility
func ResolveDynamicCommand(agent *Agent, command uint32) string {
	if agent.DynamicCommands == nil {
		// No dynamic commands, use static resolution
		logger.Error(fmt.Sprintf("⚠️  Agent %s has NO DYNAMIC COMMANDS! Using static resolution for 0x%08x", agent.NameID, command))
		return ResolveStaticCommand(command)
	}
	
	// Check all 22 base commands from agent DemonCommands array
	switch command {
	case agent.DynamicCommands.Sleep:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → SLEEP (static: %d)", agent.NameID, command, COMMAND_SLEEP))
		CommandStats.DynamicUsage["SLEEP"]++
		return "SLEEP"
	case agent.DynamicCommands.Checkin:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → CHECKIN (static: %d)", agent.NameID, command, COMMAND_CHECKIN))
		CommandStats.DynamicUsage["CHECKIN"]++
		return "CHECKIN"
	case agent.DynamicCommands.Job:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → JOB (static: %d)", agent.NameID, command, COMMAND_JOB))
		CommandStats.DynamicUsage["JOB"]++
		return "JOB"
	case agent.DynamicCommands.Proc:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → PROCESS (static: %d)", agent.NameID, command, COMMAND_PROC))
		CommandStats.DynamicUsage["PROCESS"]++
		return "PROCESS"
	case agent.DynamicCommands.ProcList:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → PROCESS_LIST (static: %d)", agent.NameID, command, COMMAND_PROC_LIST))
		CommandStats.DynamicUsage["PROCESS_LIST"]++
		return "PROCESS_LIST"
	case agent.DynamicCommands.FS:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → FILESYSTEM (static: %d)", agent.NameID, command, COMMAND_FS))
		CommandStats.DynamicUsage["FILESYSTEM"]++
		return "FILESYSTEM"
	case agent.DynamicCommands.InlineExecute:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → INLINE_EXECUTE (static: %d)", agent.NameID, command, COMMAND_INLINEEXECUTE))
		CommandStats.DynamicUsage["INLINE_EXECUTE"]++
		return "INLINE_EXECUTE"
	case agent.DynamicCommands.AssemblyInlineExecute:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → ASSEMBLY_INLINE_EXECUTE (static: %d)", agent.NameID, command, COMMAND_ASSEMBLY_INLINE_EXECUTE))
		CommandStats.DynamicUsage["ASSEMBLY_INLINE_EXECUTE"]++
		return "ASSEMBLY_INLINE_EXECUTE"
	case agent.DynamicCommands.AssemblyVersions:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → ASSEMBLY_VERSIONS (static: %d)", agent.NameID, command, COMMAND_ASSEMBLY_VERSIONS))
		CommandStats.DynamicUsage["ASSEMBLY_VERSIONS"]++
		return "ASSEMBLY_VERSIONS"
	case agent.DynamicCommands.Config:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → CONFIG (static: %d)", agent.NameID, command, COMMAND_CONFIG))
		CommandStats.DynamicUsage["CONFIG"]++
		return "CONFIG"
	case agent.DynamicCommands.Screenshot:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → SCREENSHOT (static: %d)", agent.NameID, command, COMMAND_SCREENSHOT))
		CommandStats.DynamicUsage["SCREENSHOT"]++
		return "SCREENSHOT"
	case agent.DynamicCommands.Pivot:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → PIVOT (static: %d)", agent.NameID, command, COMMAND_PIVOT))
		CommandStats.DynamicUsage["PIVOT"]++
		return "PIVOT"
	case agent.DynamicCommands.Net:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → NET (static: %d)", agent.NameID, command, COMMAND_NET))
		CommandStats.DynamicUsage["NET"]++
		return "NET"
	case agent.DynamicCommands.InjectDLL:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → INJECT_DLL (static: %d)", agent.NameID, command, COMMAND_INJECT_DLL))
		CommandStats.DynamicUsage["INJECT_DLL"]++
		return "INJECT_DLL"
	case agent.DynamicCommands.InjectShellcode:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → INJECT_SHELLCODE (static: %d)", agent.NameID, command, COMMAND_INJECT_SHELLCODE))
		CommandStats.DynamicUsage["INJECT_SHELLCODE"]++
		return "INJECT_SHELLCODE"
	case agent.DynamicCommands.SpawnDLL:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → SPAWN_DLL (static: %d)", agent.NameID, command, COMMAND_SPAWN_DLL))
		CommandStats.DynamicUsage["SPAWN_DLL"]++
		return "SPAWN_DLL"
	case agent.DynamicCommands.Token:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → TOKEN (static: %d)", agent.NameID, command, COMMAND_TOKEN))
		CommandStats.DynamicUsage["TOKEN"]++
		return "TOKEN"
	case agent.DynamicCommands.Transfer:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → TRANSFER (static: %d)", agent.NameID, command, COMMAND_TRANSFER))
		CommandStats.DynamicUsage["TRANSFER"]++
		return "TRANSFER"
	case agent.DynamicCommands.Socket:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → SOCKET (static: %d)", agent.NameID, command, COMMAND_SOCKET))
		CommandStats.DynamicUsage["SOCKET"]++
		return "SOCKET"
	case agent.DynamicCommands.Kerberos:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → KERBEROS (static: %d)", agent.NameID, command, COMMAND_KERBEROS))
		CommandStats.DynamicUsage["KERBEROS"]++
		return "KERBEROS"
	case agent.DynamicCommands.MemFile:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → MEM_FILE (static: %d)", agent.NameID, command, COMMAND_MEM_FILE))
		CommandStats.DynamicUsage["MEM_FILE"]++
		return "MEM_FILE"
	case agent.DynamicCommands.Exit:
		logger.Debug(fmt.Sprintf("Agent %s DYNAMIC command: 0x%08x → EXIT (static: %d)", agent.NameID, command, DEMON_EXIT))
		CommandStats.DynamicUsage["EXIT"]++
		return "EXIT"
	default:
		// Fall back to static command resolution
		staticResolution := ResolveStaticCommand(command)
		if staticResolution != "UNKNOWN" {
			logger.Warn(fmt.Sprintf("⚠️  Agent %s USING STATIC FALLBACK: 0x%08x → %s (DYNAMIC SYSTEM BYPASSED!)", agent.NameID, command, staticResolution))
			CommandStats.StaticUsage[staticResolution]++
		} else {
			logger.Debug(fmt.Sprintf("Agent %s UNKNOWN command: 0x%08x", agent.NameID, command))
		}
		return staticResolution
	}
}

// ResolveStaticCommand provides backward compatibility with static commands
func ResolveStaticCommand(command uint32) string {
	switch command {
	case COMMAND_FS:
		return "FILESYSTEM"
	case COMMAND_TOKEN:
		return "TOKEN"
	case COMMAND_PROC:
		return "PROCESS"
	case COMMAND_INLINEEXECUTE:
		return "INLINE_EXECUTE"
	case COMMAND_CONFIG:
		return "CONFIG"
	default:
		return "UNKNOWN"
	}
}

// Command usage statistics for verification
var CommandStats struct {
	DynamicUsage map[string]int  // Track dynamic command usage
	StaticUsage  map[string]int  // Track static command fallback
}

func init() {
	CommandStats.DynamicUsage = make(map[string]int)
	CommandStats.StaticUsage = make(map[string]int)
}

// LogCommandStats prints current command usage statistics
func LogCommandStats() {
	logger.Debug("=== COMMAND USAGE STATISTICS ===")
	logger.Debug("DYNAMIC Command Usage:")
	for cmd, count := range CommandStats.DynamicUsage {
		logger.Debug(fmt.Sprintf("  %s: %d times", cmd, count))
	}
	logger.Debug("STATIC Command Fallback:")
	for cmd, count := range CommandStats.StaticUsage {
		logger.Debug(fmt.Sprintf("  %s: %d times", cmd, count))
	}
	
	dynamicTotal := 0
	staticTotal := 0
	for _, count := range CommandStats.DynamicUsage {
		dynamicTotal += count
	}
	for _, count := range CommandStats.StaticUsage {
		staticTotal += count
	}
	
	if dynamicTotal+staticTotal > 0 {
		dynamicPercent := (float64(dynamicTotal) / float64(dynamicTotal+staticTotal)) * 100
		logger.Debug(fmt.Sprintf("Dynamic Command Coverage: %.1f%% (%d/%d)", 
			dynamicPercent, dynamicTotal, dynamicTotal+staticTotal))
	}
	logger.Debug("================================")
}

const (
	/*
	 * https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile
	 * Pipe write operations across a network are limited in size per write.
	 * The amount varies per platform. For x86 platforms it's 63.97 MB.
	 * For x64 platforms it's 31.97 MB. For Itanium it's 63.95 MB.
	 */
	// we are using 30 MB
	DEMON_MAX_RESPONSE_LENGTH = 0x1e00000
)

const (
	PROCESS_ARCH_UNKNOWN = 0
	PROCESS_ARCH_X86     = 1
	PROCESS_ARCH_X64     = 2
	PROCESS_ARCH_IA64    = 3
)

// TODO: change Command IDs. use something more readable and understandable.
const (
	COMMAND_GET_JOB                 = 1
	DEMON_INIT                      = 99
	COMMAND_CHECKIN                 = 100
	COMMAND_NOJOB                   = 10
	COMMAND_SLEEP                   = 11
	COMMAND_PROC                    = 0x1010
	COMMAND_PS_IMPORT               = 0x1011
	COMMAND_PROC_LIST               = 12
	COMMAND_FS                      = 15
	COMMAND_INLINEEXECUTE           = 20
	COMMAND_ASSEMBLY_INLINE_EXECUTE = 0x2001
	COMMAND_ASSEMBLY_LIST_VERSIONS  = 0x2003
	COMMAND_JOB                     = 21
	COMMAND_INJECT_DLL              = 22
	COMMAND_INJECT_SHELLCODE        = 24
	COMMAND_SPAWN_DLL               = 26  // Fixed naming from SPAWNDLL
	COMMAND_SPAWNDLL                = 26  // Legacy alias
	COMMAND_PROC_PPIDSPOOF          = 27
	COMMAND_TOKEN                   = 40
	COMMAND_NET                     = 2100
	COMMAND_CONFIG                  = 2500
	COMMAND_SCREENSHOT              = 2510
	COMMAND_PIVOT                   = 2520
	COMMAND_TRANSFER                = 2530
	COMMAND_SOCKET                  = 2540
	COMMAND_KERBEROS                = 2550
	COMMAND_MEM_FILE                = 2560
	COMMAND_PACKAGE_DROPPED         = 2570

	DEMON_INFO = 89
	DEMON_EXIT = 92  // Main exit command

	COMMAND_OUTPUT    = 90
	COMMAND_ERROR     = 91
	COMMAND_EXIT      = 92
	COMMAND_KILL_DATE = 93
	BEACON_OUTPUT     = 94

	// Assembly command aliases
	COMMAND_ASSEMBLY_VERSIONS       = COMMAND_ASSEMBLY_LIST_VERSIONS

	COMMAND_INLINEEXECUTE_EXCEPTION        = 1
	COMMAND_INLINEEXECUTE_SYMBOL_NOT_FOUND = 2
	COMMAND_INLINEEXECUTE_RAN_OK           = 3
	COMMAND_INLINEEXECUTE_COULD_NO_RUN     = 4

	COMMAND_EXCEPTION        = 0x98
	COMMAND_SYMBOL_NOT_FOUND = 0x99

	CALLBACK_OUTPUT      = 0x0
	CALLBACK_OUTPUT_OEM  = 0x1e
	CALLBACK_ERROR       = 0x0d
	CALLBACK_OUTPUT_UTF8 = 0x20
	CALLBACK_FILE        = 0x02
	CALLBACK_FILE_WRITE  = 0x08
	CALLBACK_FILE_CLOSE  = 0x09
)

const (
	CONFIG_IMPLANT_SPFTHREADSTART  = 3
	CONFIG_IMPLANT_SLEEP_TECHNIQUE = 5

	CONFIG_IMPLANT_VERBOSE         = 4
	CONFIG_IMPLANT_COFFEE_THREADED = 6
	CONFIG_IMPLANT_COFFEE_VEH      = 7

	CONFIG_MEMORY_ALLOC   = 101
	CONFIG_MEMORY_EXECUTE = 102

	CONFIG_INJECT_TECHNIQUE = 150
	CONFIG_INJECT_SPOOFADDR = 151
	CONFIG_INJECT_SPAWN64   = 152
	CONFIG_INJECT_SPAWN32   = 153

	CONFIG_KILLDATE     = 154
	CONFIG_WORKINGHOURS = 155

	DEMON_NET_COMMAND_DOMAIN     = 1
	DEMON_NET_COMMAND_LOGONS     = 2
	DEMON_NET_COMMAND_SESSIONS   = 3
	DEMON_NET_COMMAND_COMPUTER   = 4
	DEMON_NET_COMMAND_DCLIST     = 5
	DEMON_NET_COMMAND_SHARE      = 6
	DEMON_NET_COMMAND_LOCALGROUP = 7
	DEMON_NET_COMMAND_GROUP      = 8
	DEMON_NET_COMMAND_USERS      = 9

	DEMON_PIVOT_LIST           = 1
	DEMON_PIVOT_SMB_CONNECT    = 10
	DEMON_PIVOT_SMB_DISCONNECT = 11
	DEMON_PIVOT_SMB_COMMAND    = 12

	DEMON_INFO_MEM_ALLOC   = 10
	DEMON_INFO_MEM_EXEC    = 11
	DEMON_INFO_MEM_PROTECT = 12
	DEMON_INFO_PROC_CREATE = 21

	DEMON_COMMAND_JOB_LIST        = 1
	DEMON_COMMAND_JOB_SUSPEND     = 2
	DEMON_COMMAND_JOB_RESUME      = 3
	DEMON_COMMAND_JOB_KILL_REMOVE = 4
	DEMON_COMMAND_JOB_DIED        = 5

	DEMON_COMMAND_TRANSFER_LIST   = 0
	DEMON_COMMAND_TRANSFER_STOP   = 1
	DEMON_COMMAND_TRANSFER_RESUME = 2
	DEMON_COMMAND_TRANSFER_REMOVE = 3

	DEMON_COMMAND_PROC_MODULES = 2
	DEMON_COMMAND_PROC_GREP    = 3
	DEMON_COMMAND_PROC_CREATE  = 4
	DEMON_COMMAND_PROC_MEMORY  = 6
	DEMON_COMMAND_PROC_KILL    = 7

	DEMON_COMMAND_TOKEN_IMPERSONATE      = 1
	DEMON_COMMAND_TOKEN_STEAL            = 2
	DEMON_COMMAND_TOKEN_LIST             = 3
	DEMON_COMMAND_TOKEN_PRIVSGET_OR_LIST = 4
	DEMON_COMMAND_TOKEN_MAKE             = 5
	DEMON_COMMAND_TOKEN_GET_UID          = 6
	DEMON_COMMAND_TOKEN_REVERT           = 7
	DEMON_COMMAND_TOKEN_REMOVE           = 8
	DEMON_COMMAND_TOKEN_CLEAR            = 9
	DEMON_COMMAND_TOKEN_FIND_TOKENS      = 10

	DEMON_COMMAND_FS_DIR      = 1
	DEMON_COMMAND_FS_DOWNLOAD = 2
	DEMON_COMMAND_FS_UPLOAD   = 3
	DEMON_COMMAND_FS_CD       = 4
	DEMON_COMMAND_FS_REMOVE   = 5
	DEMON_COMMAND_FS_MKDIR    = 6
	DEMON_COMMAND_FS_COPY     = 7
	DEMON_COMMAND_FS_MOVE     = 8
	DEMON_COMMAND_FS_GET_PWD  = 9
	DEMON_COMMAND_FS_CAT      = 10
)

const (
	DOTNET_INFO_PATCHED     = 0x1
	DOTNET_INFO_NET_VERSION = 0x2
	DOTNET_INFO_ENTRYPOINT  = 0x3
	DOTNET_INFO_FINISHED    = 0x4
	DOTNET_INFO_FAILED      = 0x5
)

const (
	HAVOC_CONSOLE_MESSAGE = 0x80
	HAVOC_BOF_CALLBACK    = 0x81
)

const (
	ERROR_WIN32_LASTERROR = 1
	ERROR_TOKEN           = 3
)

const (
	SOCKET_COMMAND_RPORTFWD_ADD    = 0x0
	SOCKET_COMMAND_RPORTFWD_ADDLCL = 0x1
	SOCKET_COMMAND_RPORTFWD_LIST   = 0x2
	SOCKET_COMMAND_RPORTFWD_CLEAR  = 0x3
	SOCKET_COMMAND_RPORTFWD_REMOVE = 0x4

	SOCKET_COMMAND_SOCKSPROXY_ADD    = 0x5
	SOCKET_COMMAND_SOCKSPROXY_LIST   = 0x6
	SOCKET_COMMAND_SOCKSPROXY_REMOVE = 0x7
	SOCKET_COMMAND_SOCKSPROXY_CLEAR  = 0x8

	SOCKET_COMMAND_OPEN    = 0x10
	SOCKET_COMMAND_READ    = 0x11
	SOCKET_COMMAND_WRITE   = 0x12
	SOCKET_COMMAND_CLOSE   = 0x13
	SOCKET_COMMAND_CONNECT = 0x14

	SOCKET_TYPE_REVERSE_PORTFWD = 0x1
	SOCKET_TYPE_REVERSE_PROXY   = 0x2
	SOCKET_TYPE_CLIENT          = 0x3

	SOCKET_ERROR_ALREADY_BOUND = 0x1
)

const (
	KERBEROS_COMMAND_LUID  = 0x0
	KERBEROS_COMMAND_KLIST = 0x1
	KERBEROS_COMMAND_PURGE = 0x2
	KERBEROS_COMMAND_PTT   = 0x3
)

const (
	COFFEELDR_FLAG_NON_THREADED = 0
	COFFEELDR_FLAG_THREADED     = 1
	COFFEELDR_FLAG_DEFAULT      = 2
)

const (
	INJECT_WAY_SPAWN   = 0
	INJECT_WAY_INJECT  = 1
	INJECT_WAY_EXECUTE = 2
)

const (
	THREAD_METHOD_DEFAULT            = 0
	THREAD_METHOD_CREATEREMOTETHREAD = 1
	THREAD_METHOD_NTCREATETHREADEX   = 2
	THREAD_METHOD_NTQUEUEAPCTHREAD   = 3
	
	/* Thread execution methods */
	INJECTION_TECHNIQUE_CALLBACK         = 9
	INJECTION_TECHNIQUE_FIBER            = 10  
	INJECTION_TECHNIQUE_EXCEPTION        = 11
	INJECTION_TECHNIQUE_WORKITEM         = 12
	
	/* Threadless injection techniques */
	INJECTION_TECHNIQUE_WINDOW_PROC      = 13
	INJECTION_TECHNIQUE_VECTORED_EH      = 14
	INJECTION_TECHNIQUE_ATOM_BOMB        = 15
	
	/* Legacy injection techniques (kept for compatibility) */
	INJECTION_TECHNIQUE_PROCESS_HOLLOW   = 4
	INJECTION_TECHNIQUE_MODULE_STOMP     = 5
	INJECTION_TECHNIQUE_THREAD_HIJACK    = 6
	INJECTION_TECHNIQUE_MANUAL_MAP       = 7
	INJECTION_TECHNIQUE_EXCEPTION_HOOK   = 8
)

const (
	SecurityAnonymous      = 0x0
	SecurityIdentification = 0x1
	SecurityImpersonation  = 0x2
	SecurityDelegation     = 0x3
)

const (
	SECURITY_MANDATORY_UNTRUSTED_RID         = 0x00000000
	SECURITY_MANDATORY_LOW_RID               = 0x00001000
	SECURITY_MANDATORY_MEDIUM_RID            = 0x00002000
	SECURITY_MANDATORY_HIGH_RID              = 0x00003000
	SECURITY_MANDATORY_SYSTEM_RID            = 0x00004000
	SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x00005000
)

const (
	TokenPrimary       = 1
	TokenImpersonation = 2
)

const (
	INJECT_ERROR_SUCCESS               = 0
	INJECT_ERROR_FAILED                = 1
	INJECT_ERROR_INVALID_PARAM         = 2
	INJECT_ERROR_PROCESS_ARCH_MISMATCH = 3
)
