#ifndef DEMON_PROCESS_WORKLOAD_H
#define DEMON_PROCESS_WORKLOAD_H

#include <windows.h>

// =============================================================================
// COMPUTATIONAL DELAY FUNCTIONS - LEGITIMATE NAMING CONVENTION
// =============================================================================

/**
 * Internal processing delay function
 * @param delayMs - delay in MILLISECONDS (500 = 0.5 seconds, 1000 = 1 second)
 */
VOID ProcessWorkloadDelay(DWORD delayMs);

/**
 * Processing delay with variance
 * @param baseDelayMs - base delay in MILLISECONDS
 * @param variance - percentage variance (0-100)
 */
VOID ProcessWorkloadDelayEx(DWORD baseDelayMs, DWORD variance);

/**
 * Adaptive processing delay that calibrates to system performance
 * @param targetSeconds - approximate seconds to delay
 */
VOID ProcessAdaptiveWorkload(DWORD targetSeconds);

/**
 * Advanced processing workload with anti-analysis features
 * @param delayValue - processing workload value
 * @param antiAnalysis - enable anti-analysis features
 */
VOID ProcessWorkloadAdvanced(DWORD delayValue, BOOL antiAnalysis);

#endif
