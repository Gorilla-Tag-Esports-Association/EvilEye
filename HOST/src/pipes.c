#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "headers/pipes.h"

#define PIPE_NAME "\\\\.\\pipe\\"

int Pipe(){

    const char *pipeName = PIPE_NAME;
    char buffer[1024];
    DWORD BytesRead;

    HANDLE hPipe = CreateNamedPipeA(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        1024 * 16, 
        1024 * 16, 
        0,         
        NULL
    );

    if(hPipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to create named pipe: %ld\n", GetLastError());
        return 1;
    }
    printf("client connection or something \n");
    BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if(!connected) {
        fprintf(stderr, "Failed to connect named pipe: %ld\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }
    BOOL result = ReadFile(
        hPipe,
        buffer,
        sizeof(buffer) - 1,
        &BytesRead,
        NULL
    );
    if(!result){
        fprintf(stderr, "Failed to read from named pipe: %ld\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }
    buffer[BytesRead] = '\0'; 
    printf("Received from client: %s\n", buffer);
    const char *response = "Hello twin";
    DWORD BytesWritten;
    result = WriteFile(
        hPipe,
        response,
        (DWORD)strlen(response),
        &BytesWritten,
        NULL
    );
    CloseHandle(hPipe);
    return 0;
}