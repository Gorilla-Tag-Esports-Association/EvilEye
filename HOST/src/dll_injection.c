#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <psapi.h>

// Define a shellcode for the remote thread. This shellcode will call the DLL's entry point.
// We're using a struct to pass the necessary data to the shellcode.
// Using ULONGLONG for addresses to be compatible with 64-bit systems.
typedef struct _INJECT_DATA
{
    ULONGLONG pDllMain;
    ULONGLONG dwBaseAddress;
    DWORD  dwDllReason;
} INJECT_DATA, *PINJECT_DATA;

// This is the shellcode that will be executed in the remote process.
// It resolves imports and then calls DllMain.
DWORD WINAPI Shellcode(INJECT_DATA* pInjectData)
{
    // Call the DllMain of the injected DLL
    // The DllMain function signature is BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
    ((BOOL (WINAPI*)(HMODULE, DWORD, LPVOID))pInjectData->pDllMain)(
        (HMODULE)pInjectData->dwBaseAddress,
        pInjectData->dwDllReason,
        NULL
    );

    // This thread will exit after calling DllMain
    return 0;
}

// Forward declaration of the helper function to avoid conflicting types error
DWORD GetProcessIdByName(const char* szProcessName);

// ManualMap function to inject a DLL into a process
BOOL ManualMap(DWORD dwProcessId, const char* szDllPath)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    LPVOID pImageBase = NULL;
    LPVOID pAllocatedShellcode = NULL;
    // Use DWORD for file size and bytes read from the file, as ReadFile and GetFileSize use DWORD.
    DWORD dwFileSize = 0;
    DWORD dwBytesRead = 0;
    // Use SIZE_T for bytes written by WriteProcessMemory, as it's a 64-bit type on 64-bit systems.
    SIZE_T szBytesWritten = 0;
    BOOL bSuccess = FALSE;

    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_BASE_RELOCATION pRelocation = NULL;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;

    LPVOID pDllBuffer = NULL;
    
    // Step 1: Read the DLL file into a buffer
    hFile = CreateFileA(szDllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Error: Could not open DLL file. Error: %lu\n", GetLastError());
        return FALSE;
    }
    
    dwFileSize = GetFileSize(hFile, NULL);
    pDllBuffer = VirtualAlloc(NULL, (SIZE_T)dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pDllBuffer == NULL)
    {
        printf("Error: Could not allocate memory for DLL buffer. Error: %lu\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    if (!ReadFile(hFile, pDllBuffer, dwFileSize, &dwBytesRead, NULL) || dwBytesRead != dwFileSize)
    {
        printf("Error: Could not read DLL file. Error: %lu\n", GetLastError());
        VirtualFree(pDllBuffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    
    // Validate the headers
    pDosHeader = (PIMAGE_DOS_HEADER)pDllBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("Error: Invalid DOS signature.\n");
        VirtualFree(pDllBuffer, 0, MEM_RELEASE);
        return FALSE;
    }

    pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pDllBuffer + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("Error: Invalid NT signature.\n");
        VirtualFree(pDllBuffer, 0, MEM_RELEASE);
        return FALSE;
    }

    // Step 2: Open a handle to the target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (hProcess == NULL)
    {
        printf("Error: Could not open process. Error: %lu\n", GetLastError());
        VirtualFree(pDllBuffer, 0, MEM_RELEASE);
        return FALSE;
    }

    // Step 3: Allocate memory in the target process for the DLL
    pImageBase = VirtualAllocEx(hProcess, (LPVOID)pNtHeaders->OptionalHeader.ImageBase, (SIZE_T)pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pImageBase == NULL)
    {
        // Allocation at preferred base address failed, try again without a specific address
        pImageBase = VirtualAllocEx(hProcess, NULL, (SIZE_T)pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (pImageBase == NULL)
        {
            printf("Error: Could not allocate memory in target process. Error: %lu\n", GetLastError());
            VirtualFree(pDllBuffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return FALSE;
        }
    }
    printf("Successfully allocated memory at 0x%p in the target process.\n", pImageBase);

    // Step 4: Copy the headers to the target process
    if (!WriteProcessMemory(hProcess, pImageBase, pDllBuffer, (SIZE_T)pNtHeaders->OptionalHeader.SizeOfHeaders, &szBytesWritten) || szBytesWritten != (SIZE_T)pNtHeaders->OptionalHeader.SizeOfHeaders)
    {
        printf("Error: Could not write headers to target process. Error: %lu\n", GetLastError());
        VirtualFree(pDllBuffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Step 5: Copy each section of the DLL to the target process
    pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (!WriteProcessMemory(hProcess, (LPBYTE)pImageBase + pSectionHeader[i].VirtualAddress, (LPBYTE)pDllBuffer + pSectionHeader[i].PointerToRawData, (SIZE_T)pSectionHeader[i].SizeOfRawData, &szBytesWritten) || szBytesWritten != (SIZE_T)pSectionHeader[i].SizeOfRawData)
        {
            printf("Error: Could not write section %d to target process. Error: %lu\n", i, GetLastError());
            VirtualFree(pDllBuffer, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return FALSE;
        }
    }

    // Step 6: Perform base relocations
    // Check if relocations are needed
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
    {
        ULONGLONG ullDelta = (ULONGLONG)((LPBYTE)pImageBase - pNtHeaders->OptionalHeader.ImageBase);
        if (ullDelta != 0)
        {
            pRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)pDllBuffer + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            while (pRelocation->VirtualAddress != 0)
            {
                DWORD dwNumberOfEntries = (pRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pRelocationData = (WORD*)((LPBYTE)pRelocation + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD i = 0; i < dwNumberOfEntries; i++)
                {
                    if ((pRelocationData[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) // 32-bit relocations
                    {
                        DWORD* pAddress = (DWORD*)((LPBYTE)pDllBuffer + pRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
                        *pAddress += (DWORD)ullDelta;
                    }
                    else if ((pRelocationData[i] >> 12) == IMAGE_REL_BASED_DIR64) // 64-bit relocations
                    {
                        ULONGLONG* pAddress = (ULONGLONG*)((LPBYTE)pDllBuffer + pRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
                        *pAddress += ullDelta;
                    }
                }
                pRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)pRelocation + pRelocation->SizeOfBlock);
            }
        }
    }

    // Step 7: Resolve imports
    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
    {
        pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pDllBuffer + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDesc->Name != 0)
        {
            char* szDllName = (char*)((LPBYTE)pDllBuffer + pImportDesc->Name);
            HMODULE hModule = GetModuleHandleA(szDllName); // Get handle to the module in the local process
            if (hModule == NULL)
            {
                hModule = LoadLibraryA(szDllName);
            }
            
            if (hModule == NULL)
            {
                printf("Error: Could not load library %s. Error: %lu\n", szDllName, GetLastError());
                VirtualFree(pDllBuffer, 0, MEM_RELEASE);
                VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
                CloseHandle(hProcess);
                return FALSE;
            }

            // Get the address of the IAT
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pDllBuffer + pImportDesc->FirstThunk);
            PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pDllBuffer + pImportDesc->OriginalFirstThunk);

            while (pThunk->u1.AddressOfData != 0)
            {
                if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
                {
                    // Import by ordinal
                    pThunk->u1.Function = (ULONGLONG)GetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal));
                }
                else
                {
                    // Import by name
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)pDllBuffer + pOriginalThunk->u1.AddressOfData);
                    pThunk->u1.Function = (ULONGLONG)GetProcAddress(hModule, pImportByName->Name);
                }
                pThunk++;
                pOriginalThunk++;
            }
            pImportDesc++;
        }
    }

    // After relocations and imports are handled in the local buffer, write the modified buffer
    // back to the remote process. This is the crucial part that standard injectors miss.
    if (!WriteProcessMemory(hProcess, pImageBase, pDllBuffer, (SIZE_T)pNtHeaders->OptionalHeader.SizeOfImage, &szBytesWritten))
    {
        printf("Error: Could not write modified buffer to target process. Error: %lu\n", GetLastError());
        VirtualFree(pDllBuffer, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Step 8: Create a remote thread to execute the shellcode
    // We will allocate memory for our INJECT_DATA struct and the shellcode itself
    // and write them to the remote process.
    INJECT_DATA injectData;
    injectData.pDllMain = (ULONGLONG)pImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    injectData.dwBaseAddress = (ULONGLONG)pImageBase;
    injectData.dwDllReason = DLL_PROCESS_ATTACH;

    pAllocatedShellcode = VirtualAllocEx(hProcess, NULL, sizeof(INJECT_DATA) + 512, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pAllocatedShellcode == NULL)
    {
        printf("Error: Could not allocate shellcode memory. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Write the inject data struct
    if (!WriteProcessMemory(hProcess, pAllocatedShellcode, &injectData, sizeof(INJECT_DATA), &szBytesWritten))
    {
        printf("Error: Could not write inject data. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pAllocatedShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Write the shellcode itself
    if (!WriteProcessMemory(hProcess, (LPBYTE)pAllocatedShellcode + sizeof(INJECT_DATA), Shellcode, 512, &szBytesWritten))
    {
        printf("Error: Could not write shellcode. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pAllocatedShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    printf("Executing remote thread...\n");
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((LPBYTE)pAllocatedShellcode + sizeof(INJECT_DATA)), pAllocatedShellcode, 0, NULL);
    if (hThread == NULL)
    {
        printf("Error: Could not create remote thread. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pAllocatedShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    bSuccess = TRUE;

    // Clean up
    VirtualFreeEx(hProcess, pAllocatedShellcode, 0, MEM_RELEASE);
    VirtualFree(pDllBuffer, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return bSuccess;
}

// Helper function to find a process ID by its name
DWORD GetProcessIdByName(const char* szProcessName)
{
    DWORD dwProcessId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32))
        {
            do
            {
                if (_stricmp(pe32.szExeFile, szProcessName) == 0)
                {
                    dwProcessId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return dwProcessId;
}
