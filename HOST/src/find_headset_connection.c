#include <windows.h>
#include <setupapi.h>
#include <stdio.h>
#include <devguid.h>
#include <regstr.h>
#include "headers/find_headset_connection.h"
#include "headers/webhook_handler.h"
#pragma comment(lib, "setupapi.lib")

void find_headset_connection(){
    HDEVINFO deviceInfoset;
    SP_DEVINFO_DATA deviceInfoData;
    DWORD i;

    deviceInfoset = SetupDiGetClassDevs(NULL, "USB", NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (deviceInfoset == INVALID_HANDLE_VALUE) {
            printf("Failed to get device information set.\n");
            return;
        }
    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    for(i =0; SetupDiEnumDeviceInfo(deviceInfoset, i, &deviceInfoData); i++) {
        char hardwareId[256];
        DWORD reqsize = 0;
        if(SetupDiGetDeviceRegistryPropertyA(deviceInfoset, &deviceInfoData,
            SPDRP_HARDWAREID, NULL, (PBYTE)hardwareId,
            sizeof(hardwareId), &reqsize)){
            printf("Device %lu: %s\n", i, hardwareId);
            if (strstr(hardwareId, "VID_2833") && strstr(hardwareId, "PID_0211")) {
                printf("-> Found Valve Index headset\n");
            }
            else if (strstr(hardwareId, "VID_0BB4") && strstr(hardwareId, "PID_030E")) {
                printf("-> Found HTC Vive headset\n");
            }
            else if (strstr(hardwareId, "VID_2833") && strstr(hardwareId, "PID_0031")) {
                printf("-> Found Meta/Oculus headset\n");
            }
            }
    }

}