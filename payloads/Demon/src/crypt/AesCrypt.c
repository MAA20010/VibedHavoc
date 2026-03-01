#include <crypt/AesCrypt.h>
#include <core/MiniStd.h>

#define Nb 4

#if defined(AES256) && (AES256 == 1)
#define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
#define Nk 6
    #define Nr 12
#else
#define Nk 4        // The number of 32 bit words in a key.
#define Nr 10       // The number of rounds in AES Cipher.
#endif

#ifndef MULTIPLY_AS_A_FUNCTION
#define MULTIPLY_AS_A_FUNCTION 0
#endif

typedef UINT8 state_t[4][4];

// AUTOMATED SIGNATURE-BREAKING S-BOX (AUTO-GENERATED)
static UINT8 GetSBoxValueDynamic(UINT8 input) {
    // Runtime S-box generation using rotating XOR obfuscation
    static UINT8 obfuscated_sbox[256];
    static BOOL sbox_ready = FALSE;
    
    if (!sbox_ready) {
        // BEGIN_XOR_KEY_MARKER
        UINT8 xor_key[32] = {
            0xF8, 0x28, 0xF1, 0xEA, 0x24, 0xB8, 0x76, 0x94, 0x5B, 0xBD, 0xB7, 0xDA, 0x2E, 0xCE, 0xAA, 0xEB,
            0xDA, 0xA7, 0x3C, 0x8B, 0xA0, 0xB3, 0xF6, 0x99, 0x1E, 0x2D, 0xC0, 0xDB, 0xA7, 0x6B, 0xBD, 0xDA
        };
        // END_XOR_KEY_MARKER
        
        // BEGIN_SBOX_MARKER
        UINT8 encoded_sbox[256] = {
            0x9B, 0x54, 0x86, 0x91, 0xD6, 0xD3, 0x19, 0x51, 0x6B, 0xBC, 0xD0, 0xF1, 0xD0, 0x19, 0x01, 0x9D,
            0x10, 0x25, 0xF5, 0xF6, 0x5A, 0xEA, 0xB1, 0x69, 0xB3, 0xF9, 0x62, 0x74, 0x3B, 0xCF, 0xCF, 0x1A,
            0x4F, 0xD5, 0x62, 0xCC, 0x12, 0x87, 0x81, 0x58, 0x6F, 0x18, 0x52, 0x2B, 0x5F, 0x16, 0x9B, 0xFE,
            0xDE, 0x60, 0x1F, 0x48, 0xB8, 0x25, 0xF3, 0x03, 0x19, 0x3F, 0x40, 0x39, 0x4C, 0x4C, 0x0F, 0xAF,
            0xF1, 0xAB, 0xDD, 0xF0, 0x3F, 0xD6, 0x2C, 0x34, 0x09, 0x86, 0x61, 0x69, 0x07, 0x2D, 0x85, 0x6F,
            0x89, 0x76, 0x3C, 0x66, 0x80, 0x4F, 0x47, 0xC2, 0x74, 0xE6, 0x7E, 0xE2, 0xED, 0x27, 0xE5, 0x15,
            0x28, 0xC7, 0x5B, 0x11, 0x67, 0xF5, 0x45, 0x11, 0x1E, 0x44, 0xB5, 0xA5, 0x7E, 0xF2, 0x35, 0x43,
            0x8B, 0x04, 0x7C, 0x04, 0x32, 0x2E, 0xCE, 0x6C, 0xA2, 0x9B, 0x1A, 0xFA, 0xB7, 0x94, 0x4E, 0x08,
            0x35, 0x24, 0xE2, 0x06, 0x7B, 0x2F, 0x32, 0x83, 0x9F, 0x1A, 0xC9, 0xE7, 0x4A, 0x93, 0xB3, 0x98,
            0xBA, 0x26, 0x73, 0x57, 0x82, 0x99, 0x66, 0x11, 0x58, 0xC3, 0x78, 0xCF, 0x79, 0x35, 0xB6, 0x01,
            0x18, 0x1A, 0xCB, 0xE0, 0x6D, 0xBE, 0x52, 0xC8, 0x99, 0x6E, 0x1B, 0xB8, 0xBF, 0x5B, 0x4E, 0x92,
            0x3D, 0x6F, 0x0B, 0xE6, 0x2D, 0x66, 0xB8, 0x30, 0x72, 0x7B, 0x34, 0x31, 0xC2, 0x11, 0x13, 0xD2,
            0x42, 0x50, 0xD4, 0xC4, 0x38, 0x1E, 0xC2, 0x52, 0xB3, 0x60, 0xC3, 0xC5, 0x65, 0x73, 0x21, 0x61,
            0xAA, 0x99, 0x89, 0xED, 0xE8, 0xB0, 0x00, 0x97, 0x7F, 0x18, 0x97, 0x62, 0x21, 0xAA, 0xA0, 0x44,
            0x19, 0xD0, 0x69, 0xFB, 0x4D, 0x61, 0xF8, 0x00, 0xC0, 0xA3, 0x30, 0x33, 0xE0, 0x9B, 0x82, 0x34,
            0x56, 0x06, 0xB5, 0x86, 0x1F, 0x55, 0xB4, 0xF1, 0x5F, 0xB4, 0xED, 0xD4, 0x17, 0x3F, 0x06, 0xCC
        };
        // END_SBOX_MARKER
        
        // Decode S-box at runtime (breaks static signature)
        for (int i = 0; i < 256; i++) {
            UINT8 key_byte = xor_key[i % 32];
            obfuscated_sbox[i] = encoded_sbox[i] ^ key_byte;
        }
        sbox_ready = TRUE;
    }
    
    return obfuscated_sbox[input];
}

// AUTOMATED ROUND CONSTANT COMPUTATION (AUTO-GENERATED)
static UINT8 GetRoundConstant(UINT8 round) {
    // BEGIN_RCON_XOR_KEY_MARKER
    static UINT8 xor_key[32] = {
            0xF8, 0x28, 0xF1, 0xEA, 0x24, 0xB8, 0x76, 0x94, 0x5B, 0xBD, 0xB7, 0xDA, 0x2E, 0xCE, 0xAA, 0xEB,
            0xDA, 0xA7, 0x3C, 0x8B, 0xA0, 0xB3, 0xF6, 0x99, 0x1E, 0x2D, 0xC0, 0xDB, 0xA7, 0x6B, 0xBD, 0xDA
    };
    // END_RCON_XOR_KEY_MARKER
    
    // BEGIN_RCON_MARKER
    static UINT8 encoded_rcon[11] = {
        0x75, 0x29, 0xF3, 0xEE, 0x2C, 0xA8, 0x56, 0xD4, 0xDB, 0xA6, 0x81
    };
    // END_RCON_MARKER
    
    if (round < 11) {
        UINT8 key_byte = xor_key[round % 32];
        return encoded_rcon[round] ^ key_byte;
    }
    return 0;
}

#define getSBoxValue(num) GetSBoxValueDynamic(num)

void KeyExpansion(UINT8* RoundKey, const UINT8* Key)
{
    unsigned i, j, k;
    UINT8 tempa[4];

    for (i = 0; i < Nk; ++i)
    {
        RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    for (i = Nk; i < Nb * (Nr + 1); ++i)
    {
        {
            k = (i - 1) * 4;
            tempa[0]=RoundKey[k + 0];
            tempa[1]=RoundKey[k + 1];
            tempa[2]=RoundKey[k + 2];
            tempa[3]=RoundKey[k + 3];

        }

        if (i % Nk == 0)
        {
            const UINT8 u8tmp = tempa[0];
            tempa[0] = tempa[1];
            tempa[1] = tempa[2];
            tempa[2] = tempa[3];
            tempa[3] = u8tmp;

            tempa[0] = getSBoxValue(tempa[0]);
            tempa[1] = getSBoxValue(tempa[1]);
            tempa[2] = getSBoxValue(tempa[2]);
            tempa[3] = getSBoxValue(tempa[3]);

            tempa[0] = tempa[0] ^ GetRoundConstant(i/Nk);
        }

        if (i % Nk == 4)
        {
            tempa[0] = getSBoxValue(tempa[0]);
            tempa[1] = getSBoxValue(tempa[1]);
            tempa[2] = getSBoxValue(tempa[2]);
            tempa[3] = getSBoxValue(tempa[3]);
        }

        j = i * 4; k=(i - Nk) * 4;
        RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
        RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
        RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
        RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
    }
}

void AesInit( PAESCTX ctx, const PUINT8 key, const PUINT8 iv)
{
  KeyExpansion( ctx->RoundKey, key );
  MemCopy( ctx->Iv, iv, AES_BLOCKLEN );
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(UINT8 round, state_t* state, const UINT8* RoundKey)
{
    UINT8 i,j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
        }
    }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
    UINT8 i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[j][i] = getSBoxValue((*state)[j][i]);
        }
    }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
    UINT8 temp;

    // Rotate first row 1 columns to left
    temp           = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    // Rotate second row 2 columns to left
    temp           = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp           = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to left
    temp           = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}

static UINT8 xtime(UINT8 x)
{
    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
    UINT8 i;
    UINT8 Tmp, Tm, t;
    for (i = 0; i < 4; ++i)
    {
        t   = (*state)[i][0];
        Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
        Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
        Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
        Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
        Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
    }
}

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const UINT8* RoundKey) // Main
{
    UINT8 round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(0, state, RoundKey);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr rounds are executed in the loop below.
    // Last one without MixColumns()
    for (round = 1; ; ++round)
    {
        SubBytes(state);
        ShiftRows(state);
        if (round == Nr) {
            break;
        }
        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }
    // Add round key to last round
    AddRoundKey(Nr, state, RoundKey);
}

#if defined(CTR) && (CTR == 1)

void AesXCryptBuffer( PAESCTX ctx, PUINT8 buf, SIZE_T length)
{
    UINT8 buffer[AES_BLOCKLEN];

    size_t i;
    int bi;
    for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
    {
        if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in buffer */
        {
            MemCopy(buffer, ctx->Iv, AES_BLOCKLEN);
            Cipher((state_t*)buffer,ctx->RoundKey);

            // Signature-breaking IV increment (functionally identical)
            for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
            {
                UINT8 current_byte = ctx->Iv[bi];
                UINT8 incremented = current_byte + 1;
                ctx->Iv[bi] = incremented;
                
                if (incremented != 0) { // No overflow
                    break;
                }
                // Overflow occurred, continue to next byte
            }
            bi = 0;
        }
        buf[i] = (buf[i] ^ buffer[bi]);
  }
}

#endif