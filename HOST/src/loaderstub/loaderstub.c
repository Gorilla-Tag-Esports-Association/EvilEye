#include <windows.h>

typedef BOOL(WINAPI *DllMainFunc)(HINSTANCE, DWORD, LPVOID);

struct LoaderData {
    LPVOID baseAddress;
    DllMainFunc dllMain;
};

DWORD WINAPI LoaderThread(LPVOID lpParam) {
    struct LoaderData* data = (struct LoaderData*)lpParam;
    if (data && data->dllMain) {
        data->dllMain((HINSTANCE)data->baseAddress, DLL_PROCESS_ATTACH, NULL);
    }
    return 0;
}