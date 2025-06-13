#ifndef FILE_HASH_H
#define FILE_HASH_H

void hash_file(const char *file_path);
void scan_dir(const char *directory);
int verify_int(const char *hash_str);
#endif