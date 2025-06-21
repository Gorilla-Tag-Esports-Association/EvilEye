#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(NULL, "wsp", "Injected", MB_OK | MB_ICONINFORMATION);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}