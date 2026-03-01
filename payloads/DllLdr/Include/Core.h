
#include <windows.h>
#include <Macro.h>

// Using above HASH_KEY
#define NTDLL_HASH                      0xee229e69 // ntdll.dll

#define SYS_LDRLOADDLL                  0xec0718f7 // LDRLOADDLL
#define SYS_NTALLOCATEVIRTUALMEMORY     0x103b1c13 // NTALLOCATEVIRTUALMEMORY
#define SYS_NTPROTECTEDVIRTUALMEMORY    0x95617115 // NtProtectVirtualMemory
#define SYS_NTFLUSHINSTRUCTIONCACHE     0x3762cf05 // NTFLUSHINSTRUCTIONCACHE

#define DLLEXPORT                       __declspec( dllexport )
#define NAKED                           __declspec( naked )
#define FORCE_INLINE                    __forceinline
#define WIN32_FUNC( x )                 __typeof__( x ) * x;

#define U_PTR( x )                      ( ( UINT_PTR ) x )
#define C_PTR( x )                      ( ( LPVOID ) x )
#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

#define DLL_QUERY_HMODULE   6

#ifdef _WIN64
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_REL_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

typedef struct
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} U_STRING, *PU_STRING;

typedef struct
{
    struct
    {
        UINT_PTR Ntdll;
    } Modules;

    struct {
        NTSTATUS ( NTAPI *LdrLoadDll )(
                PWSTR           DllPath,
                PULONG          DllCharacteristics,
                PU_STRING       DllName,
                PVOID           *DllHandle
        );

        NTSTATUS ( NTAPI *NtAllocateVirtualMemory ) (
                HANDLE      ProcessHandle,
                PVOID       *BaseAddress,
                ULONG_PTR   ZeroBits,
                PSIZE_T     RegionSize,
                ULONG       AllocationType,
                ULONG       Protect
        );

        NTSTATUS ( NTAPI *NtProtectVirtualMemory ) (
                HANDLE  ProcessHandle,
                PVOID   *BaseAddress,
                PSIZE_T RegionSize,
                ULONG   NewProtect,
                PULONG  OldProtect
        );

        NTSTATUS ( NTAPI *NtFlushInstructionCache ) (
                HANDLE  ProcessHandle,
                PVOID   BaseAddress,
                ULONG   NumberOfBytesToFlush
        );
    } Win32;

} INSTANCE, *PINSTANCE;

typedef struct {
    WORD offset :12;
    WORD type   :4;
} *PIMAGE_RELOC;

LPVOID  KaynCaller( PVOID StartAddress );

VOID    Memcpy( PVOID Destination, PVOID source, SIZE_T Size );

PVOID   KGetModuleByHash( DWORD hash );
PVOID   KGetProcAddressByHash( PINSTANCE Instance, PVOID DllModuleBase, DWORD FunctionHash, DWORD Ordinal );
PVOID   KLoadLibrary( PINSTANCE Instance, LPSTR Module );

VOID    KResolveIAT( PINSTANCE Instance, PVOID KaynImage, PVOID IatDir );
VOID    KReAllocSections( PVOID KaynImage, PVOID ImageBase, PVOID Dir );

DWORD   KHashString( LPVOID String, SIZE_T Size );
SIZE_T  KStringLengthA( LPCSTR String );
SIZE_T  KStringLengthW( LPCWSTR String );
VOID    KMemSet( PVOID Destination, INT Value, SIZE_T Size );
SIZE_T  KCharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed );
