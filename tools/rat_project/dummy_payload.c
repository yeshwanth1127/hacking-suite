#include <windows.h>

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Minimal payload: shows a message box when injected
        MessageBoxA(NULL, "✅ Payload executed successfully!", "RAT Simulation", MB_OK | MB_ICONINFORMATION);
        break;
    }
    return TRUE;
}
