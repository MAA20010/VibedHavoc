#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>

// Hash function from your specification with configurable hash key
uint32_t hash_string(const char *str, int uppercase, uint32_t hash_key) {
    uint32_t hash = hash_key;
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

// Process a single file and update hash constants
void process_file(const char *filename, uint32_t hash_key) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Warning: Cannot open file %s\n", filename);
        return;
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
                new_hash = hash_string(symbol + 7, 1, hash_key);
            } 
            else if (strncmp(symbol, "H_MODULE_", 9) == 0) {
                should_update = true;
                char module_name[256];
                snprintf(module_name, sizeof(module_name), "%s.dll", symbol + 9);
                new_hash = hash_string(module_name, 1, hash_key);
            } 
            else if (strncmp(symbol, "H_COFFAPI_", 10) == 0) {
                const char *func_name = get_coffapi_func_name(symbol);
                if (func_name) {
                    should_update = true;
                    new_hash = hash_string(func_name, 0, hash_key);
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
}

// Print additional hash constants for Core.h files
void print_core_hashes(uint32_t hash_key) {
    printf("\n");
    printf("// =====================================================\n");
    printf("// New hashes for payloads/DllLdr/Include/Core.h\n");
    printf("// and payloads/Shellcode/Include/Core.h\n");
    printf("// Hash Key: %u (0x%x)\n", hash_key, hash_key);
    printf("// =====================================================\n");
    printf("\n");
    
    // Hash constants that appear in both Core.h files
    printf("#define NTDLL_HASH                      0x%x // ntdll.dll\n", hash_string("ntdll.dll", 1, hash_key));
    printf("\n");
    printf("#define SYS_LDRLOADDLL                  0x%x // LDRLOADDLL\n", hash_string("LDRLOADDLL", 1, hash_key));
    printf("#define SYS_NTALLOCATEVIRTUALMEMORY     0x%x // NTALLOCATEVIRTUALMEMORY\n", hash_string("NTALLOCATEVIRTUALMEMORY", 1, hash_key));
    printf("#define SYS_NTPROTECTEDVIRTUALMEMORY    0x%x // NtProtectVirtualMemory\n", hash_string("NTPROTECTVIRTUALMEMORY", 1, hash_key));
    
    // Additional hash for DllLdr Core.h
    printf("#define SYS_NTFLUSHINSTRUCTIONCACHE     0x%x // NTFLUSHINSTRUCTIONCACHE\n", hash_string("NTFLUSHINSTRUCTIONCACHE", 1, hash_key));
    printf("\n");
}

// Print BOF/Coffee symbol hashes
void print_coffee_hashes(uint32_t hash_key) {
    printf("// =====================================================\n");
    printf("// New Hashes for the ones in CoffeeLdr.c\n");
    printf("// Hash Key: %u (0x%x)\n", hash_key, hash_key);
    printf("// =====================================================\n");
    printf("\n");
    
    printf("// BOF Symbol Recognition Hashes (x64)\n");
    printf("#if _WIN64\n");
    printf("    // __imp_\n");
    printf("    #define SYMB_COF        0x%x // HashEx without upper case, VALUE = __imp_\n", hash_string("__imp_", 0, hash_key));
    printf("    #define SYMB_COF_SIZE   6\n");
    printf("    // __imp_Beacon\n");
    printf("    #define PREP_COF        0x%x // HashEx without upper case, VALUE = __imp_Beacon\n", hash_string("__imp_Beacon", 0, hash_key));
    printf("    #define PREP_COF_SIZE   ( SYMB_COF_SIZE + 6 )\n");
    printf("    // .refptr.Instance\n");
    printf("    #define INSTA_COF       0x%x // HashEx without upper case, VALUE = .refptr.Instance\n", hash_string(".refptr.Instance", 0, hash_key));
    printf("#else\n");
    printf("    // __imp__\n");
    printf("    #define SYMB_COF        0x%x // HashEx without upper case, VALUE = __imp__\n", hash_string("__imp__", 0, hash_key));
    printf("    #define SYMB_COF_SIZE   7\n");
    printf("    // __imp__Beacon\n");
    printf("    #define PREP_COF        0x%x // HashEx without upper case, VALUE = __imp__Beacon\n", hash_string("__imp__Beacon", 0, hash_key));
    printf("    #define PREP_COF_SIZE   ( SYMB_COF_SIZE + 6 )\n");
    printf("    // _Instance\n");
    printf("    #define INSTA_COF       0x%x // HashEx without upper case, VALUE = _Instance\n", hash_string("_Instance", 0, hash_key));
    printf("#endif\n");
    printf("\n");
    printf("// Note: These hashes are used for BOF symbol recognition and must match\n");
    printf("// the exact symbol strings used in COFF object files.\n");
    printf("\n");
    
    // Print file modification reminder
    printf("// =====================================================\n");
    printf("// FILES TO MODIFY WHEN UPDATING HASH ALGORITHM\n");
    printf("// =====================================================\n");
    printf("//\n");
    printf("// Hash Algorithm Implementation:\n");
    printf("//   %s\n", "payloads/Demon/src/core/Win32.c");
    printf("//   %s\n", "payloads/Shellcode/Source/Utils.c");
    printf("//\n");
    printf("// Hash Constants (Generated by this tool):\n");
    printf("//   %s\n", "payloads/Demon/include/common/Defines.h");
    printf("//   %s\n", "payloads/DllLdr/Include/Core.h");
    printf("//   %s\n", "payloads/Shellcode/Include/Core.h");
    printf("//   %s\n", "payloads/Demon/src/core/CoffeeLdr.c");
    printf("//\n");
    printf("// Additional Hash References:\n");
    printf("//   %s\n", "payloads/Demon/include/core/Win32.h");
    printf("//   %s\n", "payloads/DllLdr/Include/Macro.h");
    printf("//\n");
    printf("// Search Patterns:\n");
    printf("//   CoffeeLdr.c: Search for '__imp_Beacon' patterns\n");
    printf("//   Core.h files: Search for 'SYS_' and 'H_FUNC_' prefixes\n");
    printf("//   Defines.h: Search for '0x' hash constants\n");
    printf("//\n");
    printf("// =====================================================\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <filename> [hash_key]\n", argv[0]);
        fprintf(stderr, "       <filename>  - Input file to process (typically Defines.h)\n");
        fprintf(stderr, "       [hash_key]  - Optional hash key (default: 54383)\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "       This enhanced version processes the input file and then\n");
        fprintf(stderr, "       generates additional hashes for Core.h and CoffeeLdr.c\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "       %s Defines.h           # Use default hash key (54383)\n", argv[0]);
        fprintf(stderr, "       %s Defines.h 54383     # Use specific hash key\n", argv[0]);
        fprintf(stderr, "       %s Defines.h 0xD47F    # Use hex hash key\n", argv[0]);
        return 1;
    }

    // Parse hash key argument
    uint32_t hash_key = 54383;  // Default value
    if (argc == 3) {
        char *endptr;
        // Support both decimal and hex (0x prefix) input
        hash_key = (uint32_t)strtoul(argv[2], &endptr, 0);
        if (*endptr != '\0') {
            fprintf(stderr, "Error: Invalid hash key '%s'. Must be a number (decimal or hex with 0x prefix).\n", argv[2]);
            return 1;
        }
    }

    // Display hash key being used
    fprintf(stderr, "Using hash key: %u (0x%x)\n", hash_key, hash_key);

    // Process the main input file (typically Defines.h)
    process_file(argv[1], hash_key);
    
    // Print additional hash constants
    print_core_hashes(hash_key);
    print_coffee_hashes(hash_key);
    
    return 0;
}
