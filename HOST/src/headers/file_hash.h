#ifndef FILE_HASH_H
#define FILE_HASH_H

int check_file_hash_raw(const char *file_path, unsigned char *out_hash);
void hash_to_hex(const unsigned char *hash, char *hex_str);
int verify_int(const char *directory);
#endif