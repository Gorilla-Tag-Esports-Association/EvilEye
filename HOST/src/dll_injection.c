#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <tlhelp32.h>
#include "headers/dll_injection.h"

DWORD find_procid() {
    const char *process_name = "Gorilla Tag.exe";
    DWORD proc_id = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (strcmp(pe32.szExeFile, process_name) == 0) {
                proc_id = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return proc_id;
}

void dll_inject(const char *DLL_PATH) {
    DWORD ProcID = find_procid();
    if (ProcID == 0) {
        printf("Process not found\n");
        return;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcID);
    if (hProc == NULL) {
        printf("Failed to open process: %lu\n", GetLastError());
        return;
    }
    LPVOID pDllPath = VirtualAllocEx(hProc, NULL, strlen(DLL_PATH) + 1, MEM_COMMIT, PAGE_READWRITE);
    if(pDllPath == NULL) {
        printf("VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return;
    }
    if (!WriteProcessMemory(hProc, pDllPath, DLL_PATH, strlen(DLL_PATH) + 1, NULL)) {
        printf("WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return;
    }

    LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibAddr, pDllPath, 0, NULL);
    if (hThread == NULL) {
        printf("CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return;
    }
    printf("DLL injected successfully\n");
    CloseHandle(hThread);
    VirtualFreeEx(hProc, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hProc);
}