#include <windows.h>
#include <stdio.h>
#include "reflective_loader.h"

// Improved dynamic resolution with error handling
FARPROC GetAPI(const char* lib, const char* func) {
    HMODULE hModule = LoadLibraryA(lib);
    if (!hModule) {
        printf("[!] Failed to load %s (0x%lx)\n", lib, GetLastError());
        return NULL;
    }
    FARPROC proc = GetProcAddress(hModule, func);
    if (!proc) {
        printf("[!] Failed to resolve %s (0x%lx)\n", func, GetLastError());
    }
    return proc;
}

int reflective_load(LPVOID dll_buffer) {
    printf("[Reflective Loader] Starting injection...\n");

    // Verify DOS header
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll_buffer;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS Header\n");
        return 0;
    }

    // Verify NT headers
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)dll_buffer + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid NT Headers\n");
        return 0;
    }

    // Allocate memory for the DLL
    SIZE_T image_size = nt_headers->OptionalHeader.SizeOfImage;
    LPVOID allocated_memory = VirtualAlloc(
        (LPVOID)nt_headers->OptionalHeader.ImageBase,  // Preferred base address
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!allocated_memory) {
        allocated_memory = VirtualAlloc(NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!allocated_memory) {
            printf("[!] VirtualAlloc failed (0x%lx)\n", GetLastError());
            return 0;
        }
    }

    // Copy headers and sections
    memcpy(allocated_memory, dll_buffer, nt_headers->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        LPVOID dest = (LPVOID)((DWORD_PTR)allocated_memory + section[i].VirtualAddress);
        LPVOID src = (LPVOID)((DWORD_PTR)dll_buffer + section[i].PointerToRawData);
        memcpy(dest, src, section[i].SizeOfRawData);
    }

    // Process imports
    PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)allocated_memory +
        nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        while (import_desc->Name) {
            char* dll_name = (char*)((DWORD_PTR)allocated_memory + import_desc->Name);
            HMODULE hModule = LoadLibraryA(dll_name);
            
            if (!hModule) {
                printf("[!] Failed to load %s (0x%lx)\n", dll_name, GetLastError());
                VirtualFree(allocated_memory, 0, MEM_RELEASE);
                return 0;
            }

            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)allocated_memory + import_desc->FirstThunk);
            while (thunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                    FARPROC func = GetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal));
                    if (!func) {
                        printf("[!] Failed to resolve ordinal %llu\n", (unsigned long long)IMAGE_ORDINAL(thunk->u1.Ordinal));
                    }
                    thunk->u1.Function = (ULONGLONG)func;
                } else {
                    PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)allocated_memory + thunk->u1.AddressOfData);
                    FARPROC func = GetProcAddress(hModule, (LPCSTR)import->Name);
                    if (!func) {
                        printf("[!] Failed to resolve %s\n", import->Name);
                    }
                    thunk->u1.Function = (ULONGLONG)func;
                }
                thunk++;
            }
            import_desc++;
        }
    }

    // Process relocations (simplified version)
    DWORD_PTR delta = (DWORD_PTR)allocated_memory - nt_headers->OptionalHeader.ImageBase;
    if (delta && nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)allocated_memory +
            nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            
        while (relocation->VirtualAddress) {
            DWORD_PTR* patch = (DWORD_PTR*)((DWORD_PTR)allocated_memory + relocation->VirtualAddress);
            WORD* relocInfo = (WORD*)((DWORD_PTR)relocation + sizeof(IMAGE_BASE_RELOCATION));
            DWORD count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            
            for (DWORD i = 0; i < count; i++) {
                if (relocInfo[i] >> 12 == IMAGE_REL_BASED_HIGHLOW) {
                    DWORD_PTR* address = (DWORD_PTR*)((DWORD_PTR)patch + (relocInfo[i] & 0xFFF));
                    *address += delta;
                }
            }
            relocation = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocation + relocation->SizeOfBlock);
        }
    }

    // Call entry point
    DLLMAIN entry = (DLLMAIN)((DWORD_PTR)allocated_memory + nt_headers->OptionalHeader.AddressOfEntryPoint);
    printf("[Reflective Loader] Calling DllMain...\n");
    BOOL success = entry((HINSTANCE)allocated_memory, DLL_PROCESS_ATTACH, NULL);

    // Restore memory protections (simplified)
    DWORD old_protect;
    VirtualProtect(allocated_memory, image_size, PAGE_EXECUTE_READ, &old_protect);

    printf("[Reflective Loader] Injection %s\n", success ? "succeeded" : "failed");
    return success;
}