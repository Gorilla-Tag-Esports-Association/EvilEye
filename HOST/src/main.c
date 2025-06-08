#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "headers/file_hash.h"
#include "headers/webhook_handler.h"

int main()
{
	const char *dll_dir = "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Gorilla Tag\\Gorilla Tag_Data\\Managed";
    return verify_int(dll_dir);
}
