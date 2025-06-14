#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "headers/file_hash.h"
#include "headers/webhook_handler.h"
#include "headers/file_enum.h"
#include "headers/pipes.h"

int main()
{
    char steamPath[MAX_PATH];
    if (find_dir(steamPath, sizeof(steamPath)))
    {
        char Path[MAX_PATH];
        strncpy(Path, steamPath, MAX_PATH - 1);
        Path[MAX_PATH - 1] = '\0';
        strncat(Path, "\\steamapps\\common\\Gorilla Tag\\Gorilla Tag_Data\\Managed", MAX_PATH - strlen(Path) - 1);
        WIN32_FIND_DATA find_data;
        char search_path[MAX_PATH];
        snprintf(search_path, sizeof(search_path), "%s\\*.dll", Path);
        HANDLE hFind = FindFirstFile(search_path, &find_data);
        if(hFind != INVALID_HANDLE_VALUE){
            do {
                char full_path[MAX_PATH];
                snprintf(full_path, sizeof(full_path), "%s\\%s", Path, find_data.cFileName);
                hash_file(full_path);
            } while(FindNextFile(hFind, &find_data));
            FindClose(hFind);
        }
    }
    report_invalid_hashes();

    
}
