#include <Havoc/Service.hpp>

// Magic value pool - must match C payload implementation
uint64_t DEMON_MAGIC_POOL[32] = {
    0xACCB32ED, 0x8F7E4C21, 0x3A9B5D82, 0xE2F1C067,
    0x7B8A9F3E, 0x4D6E2A95, 0x9C8F7B12, 0x5E3A8D47,
    0xA1B2C3D4, 0xF8E7D6C5, 0x2E4F6A8B, 0x9D5C3B1A,
    0x6A7B8C9D, 0x1F2E3D4C, 0x8B9A7C6D, 0x4E5F6A7B,
    0xC3D4E5F6, 0x7A8B9C1D, 0x5E6F7A8B, 0x2D3E4F5A,
    0x9C1B2A3D, 0x6E7F8A9B, 0x3B4C5D6E, 0x8A9B1C2D,
    0x5F6A7B8C, 0x2A3B4C5D, 0x7E8F9A1B, 0x4C5D6E7F,
    0x1A2B3C4D, 0x8E9F1A2B, 0x5C6D7E8F, 0x3F4A5B6C
};

// Legacy magic value for backward compatibility
uint64_t DemonMagicValue = 0xACCB32ED;

// Check if a magic value is valid demon magic
bool IsValidDemonMagic(uint64_t magic) {
    for (int i = 0; i < 32; i++) {
        if (DEMON_MAGIC_POOL[i] == magic) {
            return true;
        }
    }
    return false;
}
