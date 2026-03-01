
#ifndef SHELLCODE_MACRO_H
#define SHELLCODE_MACRO_H

#include <windows.h>

// Obfuscated PEB access to break static signatures
static inline UINT_PTR GetPEBPtr(void) {
#ifdef _WIN64
    // Runtime calculation to avoid hardcoded 0x60 in binary
    UINT_PTR offset = 0x30;
    offset <<= 1;  // 0x30 << 1 = 0x60, computed at runtime
    return __readgsqword(offset);
#else
    // Runtime calculation to avoid hardcoded 0x30 in binary
    UINT_PTR offset = 0x18;
    offset <<= 1;  // 0x18 << 1 = 0x30, computed at runtime
    return __readfsdword(offset);
#endif
}

#ifdef _WIN64
    #define PPEB_PTR GetPEBPtr()
#else
    #define PPEB_PTR GetPEBPtr()
#endif

#define SEC( s, x )         __attribute__( ( section( "." #s "$" #x "" ) ) )
#define U_PTR( x )          ( ( UINT_PTR ) x )
#define C_PTR( x )          ( ( LPVOID ) x )
#define NtCurrentProcess()  ( HANDLE ) ( ( HANDLE ) - 1 )

#define GET_SYMBOL( x )     ( ULONG_PTR )( GetRIP( ) - ( ( ULONG_PTR ) & GetRIP - ( ULONG_PTR ) x ) )

#endif // SHELLCODE_MACRO_H