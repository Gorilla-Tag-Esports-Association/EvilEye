#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "headers/dll_injection.h"


const unsigned char loaderStub[] = {
    0x48, 0x83, 0xEC, 0x28,
    0x48, 0x85, 0xC9,
    0x74, 0x16,
    0x48, 0x8B, 0x41, 0x08,
    0x48, 0x85, 0xC0,
    0x74, 0x0D,
    0x48, 0x8B, 0x09,
    0x45, 0x31, 0xC0,
    0xBA, 0x01, 0x00, 0x00, 0x00,
    0xFF, 0xD0,
    0x31, 0xC0,
    0x48, 0x83, 0xC4, 0x28,
    0xC3,
    0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90
};

struct LoaderData {
    LPVOID baseAddress;
    FARPROC dllMain;
};

DWORD find_procid(const char *process_name) {
    DWORD proc_id = 0;
    PROCESSENTRY32 pe32 = {0};
    pe32.dwSize = sizeof(pe32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

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

BYTE *ReadDLL(const char *DLL_PATH, DWORD *outSize) {
    FILE *file = fopen(DLL_PATH, "rb");
    if (!file) return NULL;

    fseek(file, 0, SEEK_END);
    DWORD size = ftell(file);
    fseek(file, 0, SEEK_SET);

    BYTE *buffer = (BYTE *)malloc(size);
    fread(buffer, 1, size, file);
    fclose(file);

    *outSize = size;
    return buffer;
}

BOOL dll_inject(const char *DLL_PATH) {
    DWORD procID = find_procid("Gorilla Tag.exe");
    if (!procID) {
        printf("Process not found.\n");
        return FALSE;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    if (!hProc) {
        printf("OpenProcess failed: %lu\n", GetLastError());
        return FALSE;
    }

    DWORD dllSize;
    BYTE *dllBuffer = ReadDLL(DLL_PATH, &dllSize);
    if (!dllBuffer) {
        CloseHandle(hProc);
        return FALSE;
    }

    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)dllBuffer;
    IMAGE_NT_HEADERS64 *ntHeaders = (IMAGE_NT_HEADERS64 *)(dllBuffer + dosHeader->e_lfanew);

    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    LPVOID remoteImage = VirtualAllocEx(hProc, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImage) {
        printf("Remote allocation failed.\n");
        free(dllBuffer);
        CloseHandle(hProc);
        return FALSE;
    }

    // Fix relocations
    ULONGLONG delta = (ULONGLONG)remoteImage - ntHeaders->OptionalHeader.ImageBase;
    if (delta && ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        IMAGE_BASE_RELOCATION *reloc = (IMAGE_BASE_RELOCATION *)(dllBuffer +
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        DWORD size = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        DWORD processed = 0;
        while (processed < size) {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD *relData = (WORD *)(reloc + 1);
            for (DWORD i = 0; i < count; ++i) {
                DWORD type = relData[i] >> 12;
                DWORD offset = relData[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_DIR64) {
                    ULONGLONG *patch = (ULONGLONG *)(dllBuffer + reloc->VirtualAddress + offset);
                    *patch += delta;
                }
            }
            processed += reloc->SizeOfBlock;
            reloc = (IMAGE_BASE_RELOCATION *)((BYTE *)reloc + reloc->SizeOfBlock);
        }
    }

    // Import resolution
    IMAGE_IMPORT_DESCRIPTOR *importDesc = (IMAGE_IMPORT_DESCRIPTOR *)(dllBuffer +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (importDesc->Name) {
        const char *moduleName = (char *)(dllBuffer + importDesc->Name);
        HMODULE hMod = LoadLibraryA(moduleName);
        IMAGE_THUNK_DATA64 *origFirstThunk = (IMAGE_THUNK_DATA64 *)(dllBuffer + importDesc->OriginalFirstThunk);
        IMAGE_THUNK_DATA64 *firstThunk = (IMAGE_THUNK_DATA64 *)(dllBuffer + importDesc->FirstThunk);
        while (origFirstThunk->u1.AddressOfData) {
            FARPROC func;
            if (origFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                func = GetProcAddress(hMod, (LPCSTR)(origFirstThunk->u1.Ordinal & 0xFFFF));
            else {
                IMAGE_IMPORT_BY_NAME *import = (IMAGE_IMPORT_BY_NAME *)(dllBuffer + origFirstThunk->u1.AddressOfData);
                func = GetProcAddress(hMod, import->Name);
            }
            firstThunk->u1.Function = (ULONGLONG)func;
            origFirstThunk++;
            firstThunk++;
        }
        importDesc++;
    }

    // Copy headers and sections
    WriteProcessMemory(hProc, remoteImage, dllBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);
    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID localSection = dllBuffer + section[i].PointerToRawData;
        LPVOID remoteSection = (BYTE *)remoteImage + section[i].VirtualAddress;
        WriteProcessMemory(hProc, remoteSection, localSection, section[i].SizeOfRawData, NULL);
    }

    // Allocate memory for loader struct
    struct LoaderData loaderData = {
        .baseAddress = remoteImage,
        .dllMain = (FARPROC)((BYTE *)remoteImage + ntHeaders->OptionalHeader.AddressOfEntryPoint)
    };

    LPVOID remoteLoaderData = VirtualAllocEx(hProc, NULL, sizeof(loaderData), MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProc, remoteLoaderData, &loaderData, sizeof(loaderData), NULL);

    // Write the loader stub
    LPVOID remoteStub = VirtualAllocEx(hProc, NULL, sizeof(loaderStub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, remoteStub, loaderStub, sizeof(loaderStub), NULL);

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remoteStub, remoteLoaderData, 0, NULL);
    if (!hThread) {
        printf("Thread creation failed\n");
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    free(dllBuffer);

    printf("dll injected");
    return TRUE;
}
