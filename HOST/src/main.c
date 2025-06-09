#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "headers/file_hash.h"
#include "headers/webhook_handler.h"
#include "headers/file_enum.h"

int main()
{
    char steamPath[MAX_PATH];
    if(find_dir(steamPath, sizeof(steamPath)))
    {
        printf("Steam dir: %s\n", steamPath);
    }
}
