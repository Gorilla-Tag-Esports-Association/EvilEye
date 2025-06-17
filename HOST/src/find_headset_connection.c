#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openxr/openxr.h>


void find_headset_connection(){
    XrInstance instance;
    XrInstanceCreateInfo createInfo = {XR_TYPE_INSTANCE_CREATE_INFO};
    strcpy(createInfo.applicationInfo.applicationName, "EvilEye");
    createInfo.applicationInfo.engineVersion = 1;
    createInfo.applicationInfo.apiVersion = XR_CURRENT_API_VERSION;
    XrResult result = xrCreateInstance(&createInfo, &instance);

    if(XR_FAILED(result)){
        fprintf(stderr, "Failed to create OpenXR instance: %d\n", result);
        exit(EXIT_FAILURE);
    }
    XrSystemGetInfo systemInfo = {XR_TYPE_SYSTEM_GET_INFO};
    systemInfo.formFactor = XR_FORM_FACTOR_HEAD_MOUNTED_DISPLAY;
    XrSystemId systemId;
    result = xrGetSystem(instance, &systemInfo, &systemId);
    if(XR_FAILED(result)){
        fprintf(stderr, "Failed to get OpenXR system: %d\n", result);
        exit(EXIT_FAILURE);
    }
    XrSystemProperties systemProperties = {XR_TYPE_SYSTEM_PROPERTIES};
    result = xrGetSystemProperties(instance, systemId, &systemProperties);
    if(XR_FAILED(result)){
        fprintf(stderr, "Failed to get OpenXR system properties: %d\n", result);
        exit(EXIT_FAILURE);
    }

    printf("Headset: %s\n", systemProperties.systemName);
    printf("Vendor: %d\n", systemProperties.vendorId);

    xrDestroyInstance(instance);
}