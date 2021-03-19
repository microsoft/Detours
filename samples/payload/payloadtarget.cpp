#define _CRT_RAND_S
#include <stdlib.h>

#include <iostream>
#include <windows.h>
#include <detours.h>

#include "payloadguid.hpp"

HANDLE hParent = NULL;

__declspec(noreturn) void HandleApiFailure(const char* api)
{
    DWORD lastErr = GetLastError();
    std::cout << "payloadtarget.exe: " << api << " failed (" << lastErr << ')' << std::endl;

    if (hParent)
    {
        CloseHandle(hParent);
    }

    ExitProcess(1);
}

int main()
{
    DWORD payloadSize;
    void* payloadAddr = DetourFindPayloadEx(PARENT_HANDLE_PAYLOAD, &payloadSize);
    if (!payloadAddr || payloadSize != sizeof(HANDLE))
    {
        HandleApiFailure("DetourFindPayloadEx");
    }

    hParent = *static_cast<HANDLE*>(payloadAddr);

    DWORD randomPayloadSize;
    void* randomPayload = DetourFindRemotePayload(hParent, RANDOM_DATA_PAYLOAD, &randomPayloadSize);
    if (!randomPayload || randomPayloadSize != sizeof(random_payload_t))
    {
        HandleApiFailure("DetourFindRemotePayload");
    }

    random_payload_t randomData;
    if (rand_s(&randomData) != 0)
    {
        HandleApiFailure("rand_s");
    }


    if (!WriteProcessMemory(hParent, randomPayload, &randomData, sizeof(randomData), NULL))
    {
        HandleApiFailure("WriteProcessMemory");
    }

    CloseHandle(hParent);
    hParent = NULL;

    // conversion to int return type is potentially undefined
    ExitProcess(randomData);
}