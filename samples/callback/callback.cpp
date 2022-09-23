//////////////////////////////////////////////////////////////////////////////
//
//  Detours Test Program (dumpi.cpp of dumpi.exe)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <shellapi.h>
#pragma warning(push)
#if _MSC_VER > 1400
#pragma warning(disable:6102 6103) // /analyze warnings
#endif
#include <strsafe.h>
#pragma warning(pop)
#include <detours.h>


//////////////////////////////////////////////////////////////////////////////
//

DWORD GetTlsIndex()
{
    static DWORD index = TlsAlloc();
    return index;
}

struct CallbackContext
{
    const char* Name = nullptr;
    bool DetourSawCorrectCallback = false;

    CallbackContext(const char* name) : Name(name) {}
};

void __stdcall StoreContextInTLSCallback(PVOID pContext)
{
    DWORD index = GetTlsIndex();
    if (index != TLS_OUT_OF_INDEXES)
    {
        TlsSetValue(index, pContext);
    }
}

CallbackContext* GetContextInDetour()
{
    DWORD index = GetTlsIndex();
    return (index == TLS_OUT_OF_INDEXES ? nullptr : reinterpret_cast<CallbackContext*>(TlsGetValue(index)));
}

//////////////////////////////////////////////////////////////////////////////
//

static void (WINAPI* TrueSetLastError)(DWORD) = SetLastError;
static DWORD(WINAPI* TrueGetLastError)() = GetLastError;

const char* SetLastErrorName = "SetLastError";
const char* GetLastErrorName = "GetLastError";

void __stdcall SetLastErrorDetour(DWORD error)
{
    CallbackContext* context = GetContextInDetour();
    if (context)
    {
        context->DetourSawCorrectCallback = (strncmp(context->Name, SetLastErrorName, 12) == 0);
    }
    TrueSetLastError(error);
}

DWORD __stdcall GetLastErrorDetour()
{
    CallbackContext* context = GetContextInDetour();
    if (context)
    {
        context->DetourSawCorrectCallback = (strncmp(context->Name, GetLastErrorName, 12) == 0);
    }
    return TrueGetLastError();
}

//////////////////////////////////////////////////////////////////////// main.
//
int CDECL main(int, char **)
{
    DWORD error = NO_ERROR;
    CallbackContext setLastErrorContext{ SetLastErrorName };
    CallbackContext getLastErrorContext{ GetLastErrorName };

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    error = DetourAttachWithContextCallback(&(PVOID&)TrueSetLastError, SetLastErrorDetour, nullptr, nullptr, nullptr, StoreContextInTLSCallback, &setLastErrorContext);
    if (error == ERROR_NOT_SUPPORTED)
    {
        printf("callback.exe: Callback is not supported; did you compile with DETOURS_SUPPORT_CONTEXT_CALLBACK?\n");
        return HRESULT_FROM_WIN32(error);
    }
    if (error != NO_ERROR) {
        printf("callback.exe: Error detouring function: %ld\n", error);
        return HRESULT_FROM_WIN32(error);
    }
    DetourAttachWithContextCallback(&(PVOID&)TrueGetLastError, GetLastErrorDetour, nullptr, nullptr, nullptr, StoreContextInTLSCallback, &getLastErrorContext);
    error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        printf("callback.exe: Error committing attach transaction: %ld\n", error);
        return HRESULT_FROM_WIN32(error);
    }

    SetLastError(0);
    GetLastError();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)TrueSetLastError, SetLastErrorDetour);
    DetourDetach(&(PVOID&)TrueGetLastError, GetLastErrorDetour);
    error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        printf("callback.exe: Error committing detach transaction: %ld\n", error);
        return HRESULT_FROM_WIN32(error);
    }

    printf("callback.exe: SetLastError did %ssee the correct callback context!\n", (setLastErrorContext.DetourSawCorrectCallback ? "" : "NOT "));
    printf("callback.exe: GetLastError did %ssee the correct callback context!\n", (getLastErrorContext.DetourSawCorrectCallback ? "" : "NOT "));

    return 0;
}

// End of File
