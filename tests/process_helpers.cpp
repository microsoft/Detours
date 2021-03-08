//////////////////////////////////////////////////////////////////////////////
//
//  Process Test Helpers (process_helpers.cpp of unittests.exe)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#include "windows.h"
#include "process_helpers.h"

HRESULT GetProcessFileName(HANDLE process, std::wstring& filename)
{
    filename.resize(MAX_PATH);

    DWORD size = static_cast<DWORD>(filename.size()) + 1;
    if (QueryFullProcessImageNameW(process, 0, &filename[0], &size))
    {
        filename.resize(size);
        return S_OK;
    }
    else
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }
}

HRESULT CreateSuspendedCopy(TerminateOnScopeExit& wrapper)
{
    std::wstring location;
    const auto hr = GetProcessFileName(GetCurrentProcess(), location);
    if (FAILED(hr))
    {
        return hr;
    }

    STARTUPINFOW si = { sizeof(si) };
    if (!CreateProcessW(location.c_str(), nullptr, nullptr, nullptr, false, CREATE_SUSPENDED, nullptr, nullptr, &si, &wrapper.information))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    return S_OK;
}