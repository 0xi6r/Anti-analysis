/*
 * Demonstrates various integrity and anti-tampering techniques
 * CRC/hash checks, 
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// 1. CRC32 CHECKSUM - Verify code section integrity
// CRC32 lookup table
static unsigned long crc32_table[256];
static int crc32_table_computed = 0;

void make_crc32_table() {
    unsigned long c;
    int n, k;
    
    for (n = 0; n < 256; n++) {
        c = (unsigned long)n;
        for (k = 0; k < 8; k++) {
            if (c & 1)
                c = 0xedb88320L ^ (c >> 1);
            else
                c = c >> 1;
        }
        crc32_table[n] = c;
    }
    crc32_table_computed = 1;
}

unsigned long calculate_crc32(unsigned char *buf, size_t len) {
    unsigned long c = 0xffffffffL;
    size_t n;
    
    if (!crc32_table_computed)
        make_crc32_table();
    
    for (n = 0; n < len; n++) {
        c = crc32_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
    }
    
    return c ^ 0xffffffffL;
}

// Check if our own .text section has been modified
int check_text_section_crc() {
    HMODULE hModule = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    // Find .text section
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section->Name, ".text") == 0) {
            unsigned char *textStart = (unsigned char*)hModule + section->VirtualAddress;
            size_t textSize = section->Misc.VirtualSize;
            
            unsigned long current_crc = calculate_crc32(textStart, textSize);
            
            // IMPORTANT: Replace with actual CRC from clean binary
            // You need to calculate this once and hardcode it
            unsigned long expected_crc = 0x12345678;  // Placeholder
            
            printf("[*] Text section CRC32: 0x%08lX\n", current_crc);
            printf("[*] Expected CRC32: 0x%08lX\n", expected_crc);
            
            if (current_crc != expected_crc) {
                printf("[!] TAMPERING DETECTED: CRC mismatch!\n");
                return 0;
            }
            
            printf("[+] Text section integrity: OK\n");
            return 1;
        }
        section++;
    }
    
    return 0;
}

// 2. FUNCTION HASH VERIFICATION - Check specific functions
// Simple hash function
unsigned int simple_hash(unsigned char *data, size_t len) {
    unsigned int hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash;
}

// Protected function to check
void protected_function() {
    printf("[+] Protected function executing...\n");
    
    // Critical code here
    int secret = 42;
    printf("[+] Secret value: %d\n", secret);
}

int verify_function_integrity(void *func, size_t expected_size, unsigned int expected_hash) {
    unsigned char *func_bytes = (unsigned char*)func;
    unsigned int current_hash = simple_hash(func_bytes, expected_size);
    
    printf("[*] Function hash: 0x%08X\n", current_hash);
    printf("[*] Expected hash: 0x%08X\n", expected_hash);
    
    if (current_hash != expected_hash) {
        printf("[!] TAMPERING DETECTED: Function modified!\n");
        return 0;
    }
    
    printf("[+] Function integrity: OK\n");
    return 1;
}

// 3. INLINE INTEGRITY CHECKS - Scattered throughout code
#define INTEGRITY_CHECK(label) \
    do { \
        static int check_##label = 0; \
        if (check_##label != 0x42) { \
            printf("[!] Integrity check failed at: " #label "\n"); \
            exit(1); \
        } \
        check_##label = 0x42; \
    } while(0)

void function_with_inline_checks() {
    printf("[+] Starting function with inline checks\n");
    
    INTEGRITY_CHECK(point1);
    
    int x = 10;
    printf("[+] Processing: %d\n", x);
    
    INTEGRITY_CHECK(point2);
    
    x *= 2;
    printf("[+] Result: %d\n", x);
    
    INTEGRITY_CHECK(point3);
}

// 4. MEMORY CHECKSUM - Verify heap/stack data
typedef struct {
    unsigned char data[256];
    unsigned int checksum;
} ProtectedData;

void protect_data(ProtectedData *pd, const char *str) {
    strcpy((char*)pd->data, str);
    pd->checksum = simple_hash(pd->data, strlen(str));
}

int verify_data(ProtectedData *pd) {
    size_t len = strlen((char*)pd->data);
    unsigned int current = simple_hash(pd->data, len);
    
    if (current != pd->checksum) {
        printf("[!] TAMPERING DETECTED: Data modified!\n");
        printf("[!] Expected: 0x%08X, Got: 0x%08X\n", pd->checksum, current);
        return 0;
    }
    
    printf("[+] Data integrity: OK\n");
    return 1;
}

// 5. SELF-MODIFYING CODE WITH VERIFICATION
void self_modifying_with_check() {
    printf("[+] Self-modifying code with integrity check\n");
    
    // Code that modifies itself
    unsigned char code[] = {
        0xB8, 0x2A, 0x00, 0x00, 0x00,  // mov eax, 42
        0xC3                            // ret
    };
    
    // Calculate original checksum
    unsigned int original_checksum = calculate_crc32(code, sizeof(code));
    
    // Make executable
    DWORD oldProtect;
    VirtualProtect(code, sizeof(code), PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // Execute original
    int (*func)() = (int(*)())code;
    int result1 = func();
    printf("[+] Original result: %d\n", result1);
    
    // Modify code
    code[1] = 0x45;  // Change to 69
    
    // Verify modification was intentional
    unsigned int new_checksum = calculate_crc32(code, sizeof(code));
    if (new_checksum == original_checksum) {
        printf("[!] Code should have changed but didn't!\n");
        exit(1);
    }
    
    // Execute modified
    int result2 = func();
    printf("[+] Modified result: %d\n", result2);
    
    VirtualProtect(code, sizeof(code), oldProtect, &oldProtect);
}

// 6. PE HEADER VERIFICATION
int verify_pe_header() {
    HMODULE hModule = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    
    // Check DOS signature
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] TAMPERING DETECTED: Invalid DOS signature!\n");
        return 0;
    }
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    // Check PE signature
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] TAMPERING DETECTED: Invalid PE signature!\n");
        return 0;
    }
    
    // Check if sections have been added/removed
    WORD expected_sections = 5;  // Adjust based on your binary
    if (ntHeaders->FileHeader.NumberOfSections != expected_sections) {
        printf("[!] TAMPERING DETECTED: Section count mismatch!\n");
        printf("[!] Expected: %d, Got: %d\n", expected_sections, 
               ntHeaders->FileHeader.NumberOfSections);
        return 0;
    }
    
    printf("[+] PE header integrity: OK\n");
    return 1;
}

// 7. IMPORT TABLE VERIFICATION
int verify_import_table() {
    HMODULE hModule = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    
    if (importRVA == 0) {
        printf("[!] No import table found!\n");
        return 0;
    }
    
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importRVA);
    
    int dll_count = 0;
    while (importDesc->Name != 0) {
        char *dllName = (char*)((BYTE*)hModule + importDesc->Name);
        printf("[*] Imported DLL: %s\n", dllName);
        dll_count++;
        importDesc++;
    }
    
    // Check expected number of DLLs
    int expected_dlls = 3;  // Adjust for your binary
    if (dll_count != expected_dlls) {
        printf("[!] TAMPERING DETECTED: Unexpected DLL imports!\n");
        printf("[!] Expected: %d, Got: %d\n", expected_dlls, dll_count);
        return 0;
    }
    
    printf("[+] Import table integrity: OK\n");
    return 1;
}


// 8. TIMING-BASED INTEGRITY (Detect debugging during checks)
int integrity_check_with_timing() {
    DWORD start = GetTickCount();
    
    // Perform integrity check
    HMODULE hModule = GetModuleHandle(NULL);
    unsigned char *base = (unsigned char*)hModule;
    
    // Calculate checksum of first 1KB
    unsigned int checksum = simple_hash(base, 1024);
    
    DWORD elapsed = GetTickCount() - start;
    
    // Should be very fast (< 10ms)
    if (elapsed > 50) {
        printf("[!] TAMPERING DETECTED: Integrity check too slow!\n");
        printf("[!] Possible debugger interference\n");
        return 0;
    }
    
    printf("[+] Timed integrity check: OK (took %lu ms)\n", elapsed);
    return 1;
}

// 9. CONTINUOUS MONITORING THREAD
volatile int monitoring_active = 1;

DWORD WINAPI integrity_monitor_thread(LPVOID param) {
    printf("[+] Integrity monitoring thread started\n");
    
    while (monitoring_active) {
        // Check text section every 2 seconds
        if (!check_text_section_crc()) {
            printf("[!] CRITICAL: Code tampering detected!\n");
            MessageBox(NULL, "Tampering detected!", "Security Alert", MB_OK | MB_ICONERROR);
            exit(1);
        }
        
        Sleep(2000);
    }
    
    return 0;
}

void start_integrity_monitoring() {
    HANDLE hThread = CreateThread(NULL, 0, integrity_monitor_thread, NULL, 0, NULL);
    if (hThread) {
        printf("[+] Background integrity monitoring enabled\n");
        CloseHandle(hThread);
    }
}


// 10. STACK CANARY (Custom implementation)
#define STACK_CANARY 0xDEADBEEF

void function_with_canary() {
    unsigned int canary = STACK_CANARY;
    
    printf("[+] Function with stack canary\n");
    
    char buffer[64];
    strcpy(buffer, "Normal operation");
    printf("[+] Buffer: %s\n", buffer);
    
    // Check canary
    if (canary != STACK_CANARY) {
        printf("[!] TAMPERING DETECTED: Stack overflow detected!\n");
        exit(1);
    }
    
    printf("[+] Stack canary: OK\n");
}