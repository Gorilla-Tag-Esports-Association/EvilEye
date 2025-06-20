#include <windows.h>


#define PIPE_NAME "\\\\.\\pipe\\"
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
        HANDLE hPipe;
    DWORD dwWritten;
    const char *pipeName = PIPE_NAME;
    const char *message = "This is from gtag btw";

    BOOL connected = WaitNamedPipe(pipeName, 5000);
    if (!connected) {
        return 1;
    }

    hPipe = CreateFileA(
        pipeName,            
        GENERIC_WRITE,       
        0,                   
        NULL,                
        OPEN_EXISTING,      
        0,                 
        NULL);             

    if (hPipe == INVALID_HANDLE_VALUE) {
        return 1;
    }

    
    BOOL success = WriteFile(
        hPipe,               
        message,           
        (DWORD)strlen(message), 
        &dwWritten,         
        NULL);               

    if (!success) {
        CloseHandle(hPipe);
        return 1;
    }


    CloseHandle(hPipe);
    return 0;
}