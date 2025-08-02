#ifndef DLL_INJECTION_H
#define DLL_INJECTION_H
#include <windows.h>

typedef struct _INJECT_DATA
{
    LPVOID pLoadLibraryA;
    LPVOID pGetProcAddress;
    LPVOID pDllMain;
    DWORD  dwDllReason;
    DWORD  dwBaseAddress;
    char   szDllPath[MAX_PATH];
} INJECT_DATA, *PINJECT_DATA;

DWORD WINAPI Shellcode(INJECT_DATA* pInjectData);
DWORD GetProcessIdByName(const char* szProcessName);
BOOL ManualMap(DWORD dwProcessId, const char* szDllPath);

#endif