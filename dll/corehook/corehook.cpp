#include <stdio.h>
#include <windows.h>
#include "detours.h"

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    (void)hinst;
    (void)reserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {

        DetourRestoreAfterWith();

        LhBarrierProcessAttach();

        LhCriticalInitialize();

    }
    else if (dwReason == DLL_PROCESS_DETACH) {

        LhCriticalFinalize();
        
        LhBarrierProcessDetach();
    }
    return TRUE;
}