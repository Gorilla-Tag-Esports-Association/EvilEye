#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "headers/file_enum.h"

int find_dir(char* pathBuffer, DWORD bufferSize){
    HKEY hKey;
    const char* subKey = "SOFTWARE\\Valve\\Steam";

    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ | KEY_WOW64_32KEY, &hKey) != ERROR_SUCCESS){
        return  0;
    }

    if(RegQueryValueExA(hKey, "InstallPath", NULL, NULL, (LPBYTE)pathBuffer, &bufferSize) != ERROR_SUCCESS){
        RegCloseKey(hKey);
        return 0;
    }
    RegCloseKey(hKey);
    return 1;
}
