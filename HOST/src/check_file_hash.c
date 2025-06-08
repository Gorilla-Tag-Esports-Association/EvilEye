#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

int check_file_hash(const char *path){
    unsigned char buffer[8192];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    size_t bytes;
    FILE *file = fopen(path, "rb");

    if (!file) {
        perror("FILE OPEN ERROR");
        return 1;
    }

    SHA256_Init(&ctx);

    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        SHA256_Update(&ctx, buffer, bytes);
    }

    SHA256_Final(hash, &ctx);
    fclose(file);

    printf("SHA-256 (%s): ", path);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02x", hash[i]);
    printf("\n");

    return 0;
}
