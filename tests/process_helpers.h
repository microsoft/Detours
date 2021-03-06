//////////////////////////////////////////////////////
//
//  Process Test Helpers (process_helpers.h of unittests.exe)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#pragma once
#include <string>
#include <utility>

struct TerminateOnScopeExit
{
    PROCESS_INFORMATION information;

    TerminateOnScopeExit(const TerminateOnScopeExit&) = delete;
    TerminateOnScopeExit& operator=(const TerminateOnScopeExit&) = delete;

    ~TerminateOnScopeExit()
    {
        if (information.hThread)
        {
            TerminateThread(information.hThread, 0);
            CloseHandle(information.hThread);
        }

        if (information.hProcess)
        {
            TerminateProcess(information.hProcess, 0);
            CloseHandle(information.hProcess);
        }
    }
};

HRESULT GetProcessFileName(HANDLE process, std::wstring& filename);
HRESULT CreateSuspendedCopy(TerminateOnScopeExit& wrapper);
