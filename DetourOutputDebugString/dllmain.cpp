// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "DetourOutputDebugString.h"
#pragma comment(lib, "..\\lib.X64\\detours.lib") //TODO:Implement this another way in a real build system and properly get the right library for the build

VOID Mine_OutputDebugStringW(LPCWSTR a0);

void(__stdcall* Real_OutputDebugStringA)(LPCSTR a0)
= OutputDebugStringA;

void(__stdcall* Real_OutputDebugStringW)(LPCWSTR a0)
= OutputDebugStringW;

VOID Mine_OutputDebugStringW(LPCWSTR a0)
{
    //debug or log or whatever you want to do to verify this
    Real_OutputDebugStringW(L"Hooked\n");
    Real_OutputDebugStringW(a0);

}

VOID DetAttach(PVOID* ppvReal, PVOID pvMine, const char * psz)
{
    PVOID pvReal = NULL;
    if (ppvReal == NULL) {
        ppvReal = &pvReal;
    }

    LONG l = DetourAttach(ppvReal, pvMine);
    if (l != 0) {
        //TODO:This failed!!!
    }
}

VOID DetDetach(PVOID* ppvReal, PVOID pvMine, const char* psz)
{
    LONG l = DetourDetach(ppvReal, pvMine);
    if (l != 0) {
        //TODO:This failed
    }
}
#define ATTACH(x)       DetAttach(&(PVOID&)Real_##x,Mine_##x,#x)
#define DETACH(x)       DetDetach(&(PVOID&)Real_##x,Mine_##x,#x)

LONG AttachDetours(VOID)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    ATTACH(OutputDebugStringW);

    return DetourTransactionCommit();
}

LONG DetachDetours(VOID)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DETACH(OutputDebugStringW);
    
    return DetourTransactionCommit();
}
//////////////////////////////////////////////////////////////////////////////
//
// DLL module information
//
BOOL ThreadAttach(HMODULE hDll)
{
    return TRUE;
}

BOOL ThreadDetach(HMODULE hDll)
{
    return TRUE;
}

BOOL ProcessAttach(HMODULE hDll)
{
   ThreadAttach(hDll);
    LONG error = AttachDetours();
    return TRUE;
}

BOOL ProcessDetach(HMODULE hDll)
{
    ThreadDetach(hDll);
    LONG error = DetachDetours();
    return error == NO_ERROR;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    (void)hModule;
    (void)lpReserved;
    BOOL ret;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DetourRestoreAfterWith();
        return ProcessAttach(hModule);
    case DLL_PROCESS_DETACH:
        ret = ProcessDetach(hModule);
        return ret;
    case DLL_THREAD_ATTACH:
        return ThreadAttach(hModule);
    case DLL_THREAD_DETACH:
        return ThreadDetach(hModule);
    }
    return TRUE;
}

