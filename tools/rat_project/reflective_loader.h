#pragma once
#include <windows.h>

// Typedef for DLL entry point
typedef BOOL(WINAPI *DLLMAIN)(HINSTANCE, DWORD, LPVOID);

// Main function to perform reflective DLL injection
int reflective_load(LPVOID dll_buffer);
