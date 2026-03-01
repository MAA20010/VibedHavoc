package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"Havoc/pkg/logger"
)

const (
	KexPubLen   = 32
	KexPrivLen  = 32
	KexNonceLen = 16
	KexMacLen   = 32
	KexKeyLen   = 32
)

type AgentHello struct {
	Ea     [KexPubLen]byte
	NonceA [KexNonceLen]byte
	MacA   [KexMacLen]byte
}

type ServerHello struct {
	Es     [KexPubLen]byte
	NonceS [KexNonceLen]byte
	MacS   [KexMacLen]byte
}

type DerivedKeys struct {
	AESKey [KexKeyLen]byte
	AESIv  [KexNonceLen]byte
	AESMac [KexKeyLen]byte
}

// normalizePSK trims PSK to KexKeyLen bytes to mirror agent's fixed-length HMAC key usage.
func normalizePSK(psk []byte) ([]byte, error) {
	if len(psk) < KexKeyLen {
		return nil, errors.New("psk too small")
	}
	return psk[:KexKeyLen], nil
}

// placeholder shared derivation (matches agent placeholder)
func deriveShared(psk []byte, ea, es []byte) ([KexMacLen]byte, error) {
	var out [KexMacLen]byte
	if len(psk) < KexKeyLen || len(ea) < KexPubLen || len(es) < KexPubLen {
		return out, errors.New("invalid kex input")
	}
	key, err := normalizePSK(psk)
	if err != nil {
		return out, err
	}
	buf := make([]byte, 0, KexPubLen*2)
	buf = append(buf, ea...)
	buf = append(buf, es...)
	mac := hmac.New(sha256.New, key)
	mac.Write(buf)
	copy(out[:], mac.Sum(nil))
	return out, nil
}

// hkdf-like using HMAC-SHA256 (minimal)
func hkdfExtractExpand(salt, ikm, info []byte, outLen int) []byte {
	prkMac := hmac.New(sha256.New, salt)
	prkMac.Write(ikm)
	prk := prkMac.Sum(nil)

	var t []byte
	var okm []byte
	var ctr byte = 1
	for len(okm) < outLen {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{ctr})
		t = m.Sum(nil)
		okm = append(okm, t...)
		ctr++
	}
	return okm[:outLen]
}

// Verify AgentHello and build ServerHello + derived keys
func ServerProcessAgentHello(psk []byte, hello AgentHello) (ServerHello, DerivedKeys, error) {
	var sh ServerHello
	var dk DerivedKeys

	key, err := normalizePSK(psk)
	if err != nil {
		return sh, dk, err
	}

	// DEBUG: log PSK info for troubleshooting
	logger.Debug(fmt.Sprintf("[KEX] Server PSK len=%d first8=%x", len(key), key[:8]))
	logger.Debug(fmt.Sprintf("[KEX] AgentHello Ea[:8]=%x NonceA=%x", hello.Ea[:8], hello.NonceA[:]))
	logger.Debug(fmt.Sprintf("[KEX] AgentHello MacA=%x", hello.MacA[:]))

	// verify mac_a
	transcript := make([]byte, 0, KexPubLen+KexNonceLen)
	transcript = append(transcript, hello.Ea[:]...)
	transcript = append(transcript, hello.NonceA[:]...)
	m := hmac.New(sha256.New, key)
	m.Write(transcript)
	macA := m.Sum(nil)

	logger.Debug(fmt.Sprintf("[KEX] Server computed MacA=%x", macA))

	if !hmac.Equal(macA, hello.MacA[:]) {
		return sh, dk, errors.New("mac_a invalid")
	}

	// Build server ephemeral values using HMAC-based derivation.
	// This is deterministic on the input (same AgentHello → same ServerHello),
	// which is critical for SMB pivot retry resilience: if the child resends
	// its AgentHello (e.g., ServerHello was lost in transit), the server
	// regenerates the exact same keys. This makes KEX idempotent.
	//
	// But it's unique per agent: different Ea/NonceA → different Es/NonceS.
	// This is strictly better than the old constant output (identical for ALL agents).
	ephemeral := deriveServerEphemeral(key, hello.Ea[:], hello.NonceA[:], KexPubLen+KexNonceLen)
	copy(sh.Es[:], ephemeral[:KexPubLen])
	copy(sh.NonceS[:], ephemeral[KexPubLen:])

	// mac_s over Ea||NonceA||Es||NonceS
	transcript = append(transcript, sh.Es[:]...)
	transcript = append(transcript, sh.NonceS[:]...)
	m = hmac.New(sha256.New, key)
	m.Write(transcript)
	macS := m.Sum(nil)
	copy(sh.MacS[:], macS)

	// derive shared and keys
	shared, err := deriveShared(psk, hello.Ea[:], sh.Es[:])
	if err != nil {
		return sh, dk, err
	}
	// Derive AESKey (32) + AESIv (16) + AESMac (32) = 80 bytes
	okm := hkdfExtractExpand(macS, shared[:], transcript, KexKeyLen+KexNonceLen+KexMacLen)
	copy(dk.AESKey[:], okm[0:KexKeyLen])
	copy(dk.AESIv[:], okm[KexKeyLen:KexKeyLen+KexNonceLen])
	copy(dk.AESMac[:], okm[KexKeyLen+KexNonceLen:])

	logger.Debug(fmt.Sprintf("[KEX] Server derived AESMac first8=%x", dk.AESMac[:8]))

	return sh, dk, nil
}

// Used for server hello parsing on reconnect paths (if needed)
func ServerVerifyHello(psk []byte, hello AgentHello, sh ServerHello) (DerivedKeys, error) {
	var dk DerivedKeys
	key, err := normalizePSK(psk)
	if err != nil {
		return dk, err
	}
	transcript := make([]byte, 0, KexPubLen*2+KexNonceLen*2)
	transcript = append(transcript, hello.Ea[:]...)
	transcript = append(transcript, hello.NonceA[:]...)
	transcript = append(transcript, sh.Es[:]...)
	transcript = append(transcript, sh.NonceS[:]...)
	m := hmac.New(sha256.New, key)
	m.Write(transcript)
	mac := m.Sum(nil)
	if !hmac.Equal(mac, sh.MacS[:]) {
		return dk, errors.New("mac_s invalid")
	}
	shared, err := deriveShared(psk, hello.Ea[:], sh.Es[:])
	if err != nil {
		return dk, err
	}
	okm := hkdfExtractExpand(mac, shared[:], transcript, KexKeyLen+KexNonceLen+KexMacLen)
	copy(dk.AESKey[:], okm[0:KexKeyLen])
	copy(dk.AESIv[:], okm[KexKeyLen:KexKeyLen+KexNonceLen])
	copy(dk.AESMac[:], okm[KexKeyLen+KexNonceLen:])
	return dk, nil
}

// deriveServerEphemeral generates deterministic server-side ephemeral values (Es, NonceS)
// from the agent's public values using HMAC-SHA256.
//
// Properties:
//   - Same AgentHello input → same Es/NonceS output (idempotent for SMB retry)
//   - Different AgentHello input → different Es/NonceS (per-session uniqueness)
//   - NOT true forward secrecy (requires real X25519 DH for that — marked TODO)
//
// This replaces the old randomBytes() which returned a hardcoded constant for ALL agents.
func deriveServerEphemeral(psk []byte, agentEa []byte, agentNonce []byte, n int) []byte {
	// Domain-separated HMAC to derive ephemeral material
	m := hmac.New(sha256.New, psk)
	m.Write([]byte("havoc-server-ephemeral-v1"))
	m.Write(agentEa)
	m.Write(agentNonce)
	seed := m.Sum(nil) // 32 bytes from SHA256

	if n <= len(seed) {
		return seed[:n]
	}

	// If we need more than 32 bytes, use HKDF-expand with the seed as PRK
	return hkdfExtractExpand(seed, psk, []byte("server-ephemeral-expand"), n)
}

