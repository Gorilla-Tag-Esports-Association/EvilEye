#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "headers/pipes.h"

#define PIPE_NAME "\\\\.\\pipe\\"

int Pipe(){

    const char *pipeName = PIPE_NAME;

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
    printf("client connection or something");

}