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
    if (find_dir(steamPath, sizeof(steamPath)))
    {
        char Path[MAX_PATH];
        strncpy(Path, steamPath, MAX_PATH - 1);
        Path[MAX_PATH - 1] = '\0';
        strncat(Path, "\\steamapps\\common\\Gorilla Tag\\Gorilla Tag_Data\\Managed", MAX_PATH - strlen(Path) - 1);
        verify_int(Path);
    }
}
