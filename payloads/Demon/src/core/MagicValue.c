#include <Demon.h>

// Static storage for runtime magic value
static UINT32 g_RuntimeMagicValue = 0;
static BOOL g_MagicValueInitialized = FALSE;

// Implementation of runtime magic value selection
UINT32 GetRuntimeMagicValue() {
    if (!g_MagicValueInitialized) {
        // Use compile-time hash to select from pool
        UINT32 hash = COMPILE_TIME_HASH();
        g_RuntimeMagicValue = DEMON_MAGIC_POOL[hash % DEMON_MAGIC_POOL_SIZE];
        g_MagicValueInitialized = TRUE;
        
#ifdef DEBUG
        PRINTF( "[DEBUG::GetRuntimeMagicValue] Compile-time hash: 0x%08x\n", hash );
        PRINTF( "[DEBUG::GetRuntimeMagicValue] Pool index: %d\n", hash % DEMON_MAGIC_POOL_SIZE );
        PRINTF( "[DEBUG::GetRuntimeMagicValue] Selected magic value: 0x%08x\n", g_RuntimeMagicValue );
#endif
    }
    return g_RuntimeMagicValue;
}
