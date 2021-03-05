#include <iostream>
#include <string>
#include <windows.h>
#include <detours.h>

#include "payloadguid.hpp"

HANDLE hChildProcess = NULL;
HANDLE hChildThread = NULL;

__declspec(noreturn) void HandleApiFailure(const char* api)
{
    DWORD lastErr = GetLastError();
    std::cout << "payload.exe: " << api << " failed (" << lastErr << ')' << std::endl;

    if (hChildThread != NULL)
    {
        CloseHandle(hChildThread);
    }

    if (hChildProcess != NULL)
    {
        TerminateProcess(hChildProcess, 1);
        CloseHandle(hChildProcess);
    }

    ExitProcess(1);
}

std::wstring GetProcessFileName(HANDLE process)
{
    DWORD exeLocation_size = MAX_PATH + 1;

    std::wstring exeLocation;
    exeLocation.resize(exeLocation_size);

    if (!QueryFullProcessImageNameW(process, 0, &exeLocation[0], &exeLocation_size))
    {
        HandleApiFailure("QueryFullProcessImageNameW");
    }

    exeLocation.resize(exeLocation_size);
    return exeLocation;
}

void StartChild()
{
    std::wstring target = GetProcessFileName(GetCurrentProcess());
    target.erase(target.rfind(L'\\') + 1);
    target += L"payloadtarget.exe";

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(target.c_str(), NULL, NULL, NULL, false,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        HandleApiFailure("CreateProcessW");
    }

    hChildProcess = pi.hProcess;
    hChildThread = pi.hThread;
}

template<typename T>
volatile T* InjectPayload(HANDLE hProcess, T payload, REFGUID guid)
{
    return static_cast<volatile T*>(
        DetourCopyPayloadToProcessEx(hProcess,guid, &payload, sizeof(payload)));
}

int main()
{
    StartChild();

    // give the child a handle to ourself
    HANDLE targetHandleToParent;
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
        hChildProcess, &targetHandleToParent, 0, false, DUPLICATE_SAME_ACCESS))
    {
        HandleApiFailure("DuplicateHandle");
    }

    if (!InjectPayload(hChildProcess, targetHandleToParent, PARENT_HANDLE_PAYLOAD))
    {
        HandleApiFailure("DetourCopyPayloadToProcessEx");
    }

    // inject a payload in ourself containing zero data
    // the goal is for the child process to find this payload
    // and fill it with random data, to test DetourFindRemotePayload
    volatile random_payload_t* payloadAddr =
        InjectPayload<random_payload_t>(GetCurrentProcess(), 0, RANDOM_DATA_PAYLOAD);
    if (!payloadAddr)
    {
        HandleApiFailure("DetourCopyPayloadToProcessEx");
    }

    if (!ResumeThread(hChildThread))
    {
        HandleApiFailure("ResumeThread");
    }

    CloseHandle(hChildThread);
    hChildThread = NULL;

    if (WaitForSingleObject(hChildProcess, INFINITE) == WAIT_FAILED)
    {
        HandleApiFailure("WaitForSingleObject");
    }

    DWORD exitCode;
    if (!GetExitCodeProcess(hChildProcess, &exitCode))
    {
        HandleApiFailure("GetExitCodeProcess");
    }

    // the exit code should match the random data the child process gave us
    random_payload_t payload = *payloadAddr;
    if (exitCode == payload)
    {
        std::cout << "Success, exit code (0x" << std::uppercase << std::hex << exitCode
            << ") matches payload content (0x" << payload << ')' << std::endl;
        return 0;
    }
    else
    {
        std::cout << "Error, exit code (0x" << std::uppercase  << std::hex << exitCode
            << ") does not matches payload content (0x" << payload << ')' << std::endl;
        return 1;
    }
}