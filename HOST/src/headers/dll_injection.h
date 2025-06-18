#ifndef DLL_INJECTION_H
#define DLL_INJECTION_H
#include <windows.h>

DWORD find_procid();
void dll_inject(const char *DLL_PATH);

#endif