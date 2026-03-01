#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>

// Hash function from your specification
uint32_t hash_string(const char *str, int uppercase) {
    uint32_t hash = 236;
    int c;
    
    while ((c = *str++)) {
        if (uppercase) {
            c = toupper(c);
        }
        hash = c + (hash << 4) + c +  (hash << 13) - hash;
    }
    
    return hash;
}

// Structure for COFFAPI mapping
typedef struct {
    const char *symbol;
    const char *func_name;
} CoffApiMapping;

// COFFAPI mapping table (partial example)
CoffApiMapping coffapi_mapping[] = {
    {"H_COFFAPI_BEACONDATAPARSER", "BeaconDataParse"},
    {"H_COFFAPI_BEACONDATAINT", "BeaconDataInt"},
    {"H_COFFAPI_BEACONDATASHORT", "BeaconDataShort"},
    {"H_COFFAPI_BEACONDATALENGTH", "BeaconDataLength"},
    {"H_COFFAPI_BEACONDATAEXTRACT", "BeaconDataExtract"},
    {"H_COFFAPI_BEACONFORMATALLOC", "BeaconFormatAlloc"},
    {"H_COFFAPI_BEACONFORMATRESET", "BeaconFormatReset"},
    {"H_COFFAPI_BEACONFORMATFREE", "BeaconFormatFree"},
    {"H_COFFAPI_BEACONFORMATAPPEND", "BeaconFormatAppend"},
    {"H_COFFAPI_BEACONFORMATPRINTF", "BeaconFormatPrintf"},
    {"H_COFFAPI_BEACONFORMATTOSTRING", "BeaconFormatToString"},
    {"H_COFFAPI_BEACONFORMATINT", "BeaconFormatInt"},
    {"H_COFFAPI_BEACONPRINTF", "BeaconPrintf"},
    {"H_COFFAPI_BEACONOUTPUT", "BeaconOutput"},
    {"H_COFFAPI_BEACONUSETOKEN", "BeaconUseToken"},
    {"H_COFFAPI_BEACONREVERTTOKEN", "BeaconRevertToken"},
    {"H_COFFAPI_BEACONISADMIN", "BeaconIsAdmin"},
    {"H_COFFAPI_BEACONGETSPAWNTO", "BeaconGetSpawnTo"},
    {"H_COFFAPI_BEACONINJECTPROCESS", "BeaconInjectProcess"},
    {"H_COFFAPI_BEACONSPAWNTEMPORARYPROCESS", "BeaconSpawnTemporaryProcess"},
    {"H_COFFAPI_BEACONINJECTTEMPORARYPROCESS", "BeaconInjectTemporaryProcess"},
    {"H_COFFAPI_BEACONCLEANUPPROCESS", "BeaconCleanupProcess"},
    {"H_COFFAPI_BEACONINFORMATION", "BeaconInformation"},
    {"H_COFFAPI_BEACONADDVALUE", "BeaconAddValue"},
    {"H_COFFAPI_BEACONGETVALUE", "BeaconGetValue"},
    {"H_COFFAPI_BEACONREMOVEVALUE", "BeaconRemoveValue"},
    {"H_COFFAPI_BEACONDATASTOREGETITEM", "BeaconDataStoreGetItem"},
    {"H_COFFAPI_BEACONDATASTOREPROTECTITEM", "BeaconDataStoreProtectItem"},
    {"H_COFFAPI_BEACONDATASTOREUNPROTECTITEM", "BeaconDataStoreUnprotectItem"},
    {"H_COFFAPI_BEACONDATASTOREMAXENTRIES", "BeaconDataStoreMaxEntries"},
    {"H_COFFAPI_BEACONGETCUSTOMUSERDATA", "BeaconGetCustomUserData"},
    
    {"H_COFFAPI_TOWIDECHAR", "toWideChar"},
    {"H_COFFAPI_LOADLIBRARYA", "LoadLibraryA"},
    {"H_COFFAPI_GETMODULEHANDLE", "GetModuleHandleA"},
    {"H_COFFAPI_GETPROCADDRESS", "GetProcAddress"},
    {"H_COFFAPI_FREELIBRARY", "FreeLibrary"},
    {"H_COFFAPI_LOCALFREE", "LocalFree"},
    
    {"H_COFFAPI_NTOPENTHREAD", "NtOpenThread"},
    {"H_COFFAPI_NTOPENPROCESS", "NtOpenProcess"},
    {"H_COFFAPI_NTTERMINATEPROCESS", "NtTerminateProcess"},
    {"H_COFFAPI_NTOPENTHREADTOKEN", "NtOpenThreadToken"},
    {"H_COFFAPI_NTOPENPROCESSTOKEN", "NtOpenProcessToken"},
    {"H_COFFAPI_NTDUPLICATETOKEN", "NtDuplicateToken"},
    {"H_COFFAPI_NTQUEUEAPCTHREAD", "NtQueueApcThread"},
    {"H_COFFAPI_NTSUSPENDTHREAD", "NtSuspendThread"},
    {"H_COFFAPI_NTRESUMETHREAD", "NtResumeThread"},
    {"H_COFFAPI_NTCREATEEVENT", "NtCreateEvent"},
    {"H_COFFAPI_NTCREATETHREADEX", "NtCreateThreadEx"},
    {"H_COFFAPI_NTDUPLICATEOBJECT", "NtDuplicateObject"},
    {"H_COFFAPI_NTGETCONTEXTTHREAD", "NtGetContextThread"},
    {"H_COFFAPI_NTSETCONTEXTTHREAD", "NtSetContextThread"},
    {"H_COFFAPI_NTQUERYINFORMATIONPROCESS", "NtQueryInformationProcess"},
    {"H_COFFAPI_NTQUERYSYSTEMINFORMATION", "NtQuerySystemInformation"},
    {"H_COFFAPI_NTWAITFORSINGLEOBJECT", "NtWaitForSingleObject"},
    {"H_COFFAPI_NTALLOCATEVIRTUALMEMORY", "NtAllocateVirtualMemory"},
    {"H_COFFAPI_NTWRITEVIRTUALMEMORY", "NtWriteVirtualMemory"},
    {"H_COFFAPI_NTFREEVIRTUALMEMORY", "NtFreeVirtualMemory"},
    {"H_COFFAPI_NTUNMAPVIEWOFSECTION", "NtUnmapViewOfSection"},
    {"H_COFFAPI_NTPROTECTVIRTUALMEMORY", "NtProtectVirtualMemory"},
    {"H_COFFAPI_NTREADVIRTUALMEMORY", "NtReadVirtualMemory"},
    {"H_COFFAPI_NTTERMINATETHREAD", "NtTerminateThread"},
    {"H_COFFAPI_NTALERTRESUMETHREAD", "NtAlertResumeThread"},
    {"H_COFFAPI_NTSIGNALANDWAITFORSINGLEOBJECT", "NtSignalAndWaitForSingleObject"},
    {"H_COFFAPI_NTQUERYVIRTUALMEMORY", "NtQueryVirtualMemory"},
    {"H_COFFAPI_NTQUERYINFORMATIONTOKEN", "NtQueryInformationToken"},
    {"H_COFFAPI_NTQUERYINFORMATIONTHREAD", "NtQueryInformationThread"},
    {"H_COFFAPI_NTQUERYOBJECT", "NtQueryObject"},
    {"H_COFFAPI_NTCLOSE", "NtClose"},
    {"H_COFFAPI_NTSETINFORMATIONTHREAD", "NtSetInformationThread"},
    {"H_COFFAPI_NTSETINFORMATIONVIRTUALMEMORY", "NtSetInformationVirtualMemory"},
    {"H_COFFAPI_NTGETNEXTTHREAD", "NtGetNextThread"},
    {NULL, NULL}  // Terminator
};

// Find function name for COFFAPI symbol
const char *get_coffapi_func_name(const char *symbol) {
    for (int i = 0; coffapi_mapping[i].symbol != NULL; i++) {
        if (strcmp(symbol, coffapi_mapping[i].symbol) == 0) {
            return coffapi_mapping[i].func_name;
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "r");
    if (!file) {
        perror("Error opening file");
        return 1;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&line, &len, file)) != -1) {
        // Keep original line if it doesn't start with #define
        if (read < 8 || strncmp(line, "#define", 7) != 0) {
            fputs(line, stdout);
            continue;
        }

        // Parse the line
        char *ptr = line + 7;  // Skip "#define"
        char *symbol_start = NULL;
        char *symbol_end = NULL;
        char *hash_start = NULL;
        char *hash_end = NULL;
        char *rest = NULL;
        
        // Find symbol start
        while (*ptr && (*ptr == ' ' || *ptr == '\t')) ptr++;
        symbol_start = ptr;
        
        // Find symbol end
        while (*ptr && *ptr != ' ' && *ptr != '\t' && *ptr != '\n') ptr++;
        symbol_end = ptr;
        
        // Find hash start
        while (*ptr && (*ptr == ' ' || *ptr == '\t')) ptr++;
        if (ptr[0] == '0' && ptr[1] == 'x') {
            hash_start = ptr;
            
            // Find hash end (8 hex digits)
            hash_end = ptr + 2;
            for (int i = 0; i < 8; i++) {
                if (!isxdigit(*hash_end)) break;
                hash_end++;
            }
        }
        
        // The rest of the line
        rest = hash_end;
        
        // Extract symbol
        char symbol[256] = {0};
        if (symbol_start && symbol_end > symbol_start) {
            size_t symbol_len = symbol_end - symbol_start;
            if (symbol_len >= sizeof(symbol)) symbol_len = sizeof(symbol) - 1;
            strncpy(symbol, symbol_start, symbol_len);
            symbol[symbol_len] = '\0';
        }
        
        // Process if we have a valid symbol and hash
        if (symbol[0] && hash_start) {
            uint32_t new_hash = 0;
            bool should_update = false;
            
            if (strncmp(symbol, "H_FUNC_", 7) == 0) {
                should_update = true;
                new_hash = hash_string(symbol + 7, 1);
            } 
            else if (strncmp(symbol, "H_MODULE_", 9) == 0) {
                should_update = true;
                char module_name[256];
                snprintf(module_name, sizeof(module_name), "%s.dll", symbol + 9);
                new_hash = hash_string(module_name, 1);
            } 
            else if (strncmp(symbol, "H_COFFAPI_", 10) == 0) {
                const char *func_name = get_coffapi_func_name(symbol);
                if (func_name) {
                    should_update = true;
                    new_hash = hash_string(func_name, 0);
                }
            }
            
            if (should_update) {
                // Output the line with original formatting
                fwrite(line, 1, symbol_end - line, stdout);
                fwrite(symbol_end, 1, hash_start - symbol_end, stdout);
                printf("0x%x", new_hash);
                fputs(rest, stdout);
                continue;
            }
        }
        
        // If we get here, output the original line
        fputs(line, stdout);
    }

    free(line);
    fclose(file);
    return 0;
}
