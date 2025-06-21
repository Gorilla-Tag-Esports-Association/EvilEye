#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <tlhelp32.h>
#include "headers/dll_injection.h"

typedef BOOL(WINAPI *DllMainFunc)(HINSTANCE, DWORD, LPVOID);

BYTE *ReadDLL(const char *DLL_PATH, DWORD *outSize)
{
    FILE *file = fopen(DLL_PATH, "rb");
    if (!file)
        return NULL;

    fseek(file, 0, SEEK_END);
    DWORD size = ftell(file);
    fseek(file, 0, SEEK_SET);

    BYTE *buffer = (BYTE *)malloc(size);
    fread(buffer, 1, size, file);
    fclose(file);

    *outSize = size;
    return buffer;
    return buffer;
}

DWORD find_procid()
{
    const char *process_name = "Gorilla Tag.exe";
    DWORD proc_id = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32))
    {
        do
        {
            if (strcmp(pe32.szExeFile, process_name) == 0)
            {
                proc_id = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return proc_id;
}

BOOL dll_inject(const char *DLL_PATH)
{
    DWORD ProcID = find_procid();
    if (ProcID == 0)
    {
        printf("Process not found\n");
        return FALSE;
    }
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcID);
    if (hProc == NULL)
    {
        printf("OpenProcess failed: %lu\n", GetLastError());
        return FALSE;
    }
    DWORD dllSize;
    BYTE *dllBuffer = ReadDLL(DLL_PATH, &dllSize);
    if (dllBuffer == NULL)
    {
        printf("ReadDLL failed\n");
        CloseHandle(hProc);
        return FALSE;
    }

    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)dllBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("Invalid DLL file\n");
        free(dllBuffer);
        CloseHandle(hProc);
        return FALSE;
    }
    IMAGE_NT_HEADERS64 *NTHeader = (IMAGE_NT_HEADERS64 *)(dllBuffer + dosHeader->e_lfanew);
    if (NTHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("Invalid NT header\n");
        free(dllBuffer);
        CloseHandle(hProc);
        return FALSE;
    }
    SIZE_T DllImageSize = NTHeader->OptionalHeader.SizeOfImage;
    LPVOID remoteMemory = VirtualAllocEx(hProc, NULL, DllImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory)
    {
        printf("VirtualAllocEx failed: %lu\n", GetLastError());
        free(dllBuffer);
        CloseHandle(hProc);
        return FALSE;
    }
    if (!WriteProcessMemory(hProc, remoteMemory, dllBuffer, NTHeader->OptionalHeader.SizeOfHeaders, NULL))
    {
        printf("WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteMemory, 0, MEM_RELEASE);
        free(dllBuffer);
        CloseHandle(hProc);
        return FALSE;
    }
    IMAGE_SECTION_HEADER *sectionHeader = IMAGE_FIRST_SECTION(NTHeader);
    if (!sectionHeader)
    {
        printf("No section headers found\n");
        VirtualFreeEx(hProc, remoteMemory, 0, MEM_RELEASE);
        free(dllBuffer);
        CloseHandle(hProc);
        return FALSE;
    }
    for (unsigned int i = 0; i < NTHeader->FileHeader.NumberOfSections; ++i)
    {
        LPVOID addr = (LPVOID)((BYTE *)remoteMemory + sectionHeader[i].VirtualAddress);
        LPVOID src = (LPVOID)(dllBuffer + sectionHeader[i].PointerToRawData);
        if (!WriteProcessMemory(hProc, addr, src, sectionHeader[i].SizeOfRawData, NULL))
        {
            printf("WriteProcessMemory failed for section %u: %lu\n", i, GetLastError());
            VirtualFreeEx(hProc, remoteMemory, 0, MEM_RELEASE);
            free(dllBuffer);
            CloseHandle(hProc);
            return FALSE;
        }
    }
    ULONGLONG delta = (ULONGLONG)remoteMemory - (ULONGLONG)dllBuffer;
    if (delta != 0 && NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
    {
        IMAGE_BASE_RELOCATION *relocation = (IMAGE_BASE_RELOCATION *)(dllBuffer + NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        DWORD relocationSize = NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        DWORD processed = 0;

        while (processed < relocationSize)
        {
            DWORD count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD *relocationData = (WORD *)(relocation + 1);
            for (DWORD i = 0; i < count; ++i)
            {
                WORD typeOffset = relocationData[i];
                WORD type = typeOffset >> 12;
                WORD offset = typeOffset & 0xFFF;
                if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64)
                {
                    ULONGLONG *patchAddr = (ULONGLONG *)(dllBuffer + relocation->VirtualAddress + offset);
                    *patchAddr += delta;
                }
            }
            processed += relocation->SizeOfBlock;
            relocation = (IMAGE_BASE_RELOCATION *)((BYTE *)relocation + relocation->SizeOfBlock);
        }
    }
    if (NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
    {
        IMAGE_IMPORT_DESCRIPTOR *ImportDesc = (IMAGE_IMPORT_DESCRIPTOR *)(dllBuffer + NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (ImportDesc->Name)
        {
            char *moduleName = (char *)(dllBuffer + ImportDesc->Name);
            if (!moduleName || !*moduleName)
            {
                printf("Invalid module name in import descriptor\n");
                VirtualFreeEx(hProc, remoteMemory, 0, MEM_RELEASE);
                free(dllBuffer);
                CloseHandle(hProc);
                return FALSE;
            }
            HMODULE hModule = LoadLibraryA(moduleName);
            if (!hModule)
            {
                printf("LoadLibraryA failed for module %s: %lu\n", moduleName, GetLastError());
                VirtualFreeEx(hProc, remoteMemory, 0, MEM_RELEASE);
                free(dllBuffer);
                CloseHandle(hProc);
                return FALSE;
            }

            IMAGE_THUNK_DATA64 *OriginalFirstThunk = (IMAGE_THUNK_DATA64 *)(dllBuffer + ImportDesc->OriginalFirstThunk);
            IMAGE_THUNK_DATA64 *FirstThunk = (IMAGE_THUNK_DATA64 *)(dllBuffer + ImportDesc->FirstThunk);

            while (OriginalFirstThunk->u1.AddressOfData)
            {
                FARPROC func = NULL;
                if (OriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                {
                    WORD ordinal = (WORD)(OriginalFirstThunk->u1.Ordinal & 0xFFFF);
                    func = GetProcAddress(hModule, (LPCSTR)ordinal);
                }
                else
                {
                    IMAGE_IMPORT_BY_NAME *IIBN = (IMAGE_IMPORT_BY_NAME *)(dllBuffer + OriginalFirstThunk->u1.AddressOfData);
                    func = GetProcAddress(hModule, IIBN->Name);
                }
                if (!func)
                {
                    printf("GetProcAddress failed for function: %lu\n", GetLastError());
                    VirtualFreeEx(hProc, remoteMemory, 0, MEM_RELEASE);
                    free(dllBuffer);
                    CloseHandle(hProc);
                    return FALSE;
                }
#ifdef _WIN64
                FirstThunk->u1.Function = (ULONGLONG)func;
#else
                FirstThunk->u1.Function = (DWORD)func;
#endif
                OriginalFirstThunk++;
                FirstThunk++;
            }
        }
    }
    LPTHREAD_START_ROUTINE pThreadProc = (LPTHREAD_START_ROUTINE)((BYTE *)remoteMemory + NTHeader->OptionalHeader.AddressOfEntryPoint);
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, pThreadProc, remoteMemory, 0, NULL);
    if(!hThread)
    {
        printf("CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteMemory, 0, MEM_RELEASE);
        free(dllBuffer);
        CloseHandle(hProc);
        return FALSE;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remoteMemory, 0, MEM_RELEASE);
    free(dllBuffer);
    CloseHandle(hProc);
    return TRUE;
    printf("DLL injected successfully\n");
}