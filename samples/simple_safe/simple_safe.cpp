//////////////////////////////////////////////////////////////////////////////
//
//  Detours Test Program (simple_safe.cpp of simple_safe.dll)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  This DLL will detour the Windows SleepEx API so that TimedSleep function
//  gets called instead.  TimedSleepEx records the before and after times, and
//  calls the real SleepEx API through the TrueSleepEx function pointer.
//
//  The difference between simple and simple_safe is that simple_safe
//  uses the C++ 14 overloads which help prevent mismatching types.
//
#include <stdio.h>
#include <windows.h>
#include "detours.h"

static LONG dwSlept = 0;
static DWORD (WINAPI * TrueSleepEx)(DWORD dwMilliseconds, BOOL bAlertable) = SleepEx;

DWORD WINAPI TimedSleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    DWORD dwBeg = GetTickCount();
    DWORD ret = TrueSleepEx(dwMilliseconds, bAlertable);
    DWORD dwEnd = GetTickCount();

    InterlockedExchangeAdd(&dwSlept, dwEnd - dwBeg);

    return ret;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    LONG error;
    (void)hinst;
    (void)reserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();

        printf("simple_safe" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
               " Starting.\n");
        fflush(stdout);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&TrueSleepEx, TimedSleepEx);
        error = DetourTransactionCommit();

        if (error == NO_ERROR) {
            printf("simple_safe" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                   " Detoured SleepEx().\n");
        }
        else {
            printf("simple_safe" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                   " Error detouring SleepEx(): %ld\n", error);
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&TrueSleepEx, TimedSleepEx);
        error = DetourTransactionCommit();

        printf("simple_safe" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
               " Removed SleepEx() (result=%ld), slept %ld ticks.\n", error, dwSlept);
        fflush(stdout);
    }
    return TRUE;
}

//
///////////////////////////////////////////////////////////////// End of File.
