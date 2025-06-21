#ifndef DLL_INJECTION_H
#define DLL_INJECTION_H
#include <windows.h>

typedef BOOL(WINAPI* DllMainFunc)(HINSTANCE, DWORD, LPVOID);
BYTE* ReadDLL(const char* DLL_PATH, DWORD* outSize);
DWORD find_procid();
BOOL dll_inject(const char *DLL_PATH);

#endif