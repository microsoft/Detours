//////////////////////////////////////////////////////////////////////////////
//
//  Detour Test Program (extend.cpp of extend.dll)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  An example dynamically detouring a function.
//
#include <stdio.h>
#include <windows.h>
#include "detours.h"

static LONG nExtends = 0;
static LONG nInterns = 0;

static DWORD (WINAPI * TrueTarget)(DWORD dwCount) = NULL;
static DWORD (WINAPI * TrueHidden)(DWORD dwCount) = NULL;
static int (WINAPI * TrueEntryPoint)(VOID) = NULL;

// Extend is a detour for Target.
static DWORD WINAPI Extend(DWORD dwCount)
{
    InterlockedIncrement(&nExtends);

    printf("extend.dll: Extend    (%d) -> %d.\n", dwCount, dwCount + 1000);
    dwCount = TrueTarget(dwCount + 1000);
    printf("extend.dll: Extend    (.....) -> %d.\n", dwCount);
    return dwCount;
}

// Intern is a detour for Hidden.
static DWORD WINAPI Intern(DWORD dwCount)
{
    InterlockedIncrement(&nInterns);

    printf("extend.dll:    Intern (%d) -> %d.\n", dwCount, dwCount + 10);
    dwCount = TrueHidden(dwCount + 10);
    printf("extend.dll:    Intern (.....) -> %d.\n", dwCount);
    return dwCount;
}

static int WINAPI ExtendEntryPoint()
{
    // We couldn't call LoadLibrary in DllMain, so our functions here.
    LONG error;

    // We separate out the functions in the export table (Target)
    // from the ones that require debug symbols (Hidden).
    TrueTarget =
        (DWORD (WINAPI *)(DWORD))
        DetourFindFunction("target.dll", "Target");
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueTarget, Extend);
    error = DetourTransactionCommit();

    if (error == NO_ERROR) {
        printf("extend.dll: Detoured Target().\n");
    }
    else {
        printf("extend.dll: Error detouring Target(): %d\n", error);
    }

    // Now try to detour the functions requiring debug symbols.
    TrueHidden =
        (DWORD (WINAPI *)(DWORD))
        DetourFindFunction("target.dll", "Hidden");
    if (TrueHidden == NULL) {
        error = GetLastError();
        printf("extend.dll: TrueHidden = %p (error = %d)\n", TrueHidden, error);
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueHidden, Intern);
    error = DetourTransactionCommit();

    if (error == NO_ERROR) {
        printf("extend.dll: Detoured Hidden().\n");
    }
    else {
        printf("extend.dll: Error detouring Hidden(): %d\n", error);
    }

    // Now let the application start executing.
    printf("extend.dll: Calling EntryPoint\n");
    fflush(stdout);

    return TrueEntryPoint();
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

        printf("extend.dll: Starting.\n");
        fflush(stdout);

        // NB: DllMain can't call LoadLibrary, so we hook the app entry point.

        TrueEntryPoint = (int (WINAPI *)())DetourGetEntryPoint(NULL);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueEntryPoint, ExtendEntryPoint);
        error = DetourTransactionCommit();

        if (error == NO_ERROR) {
            printf("extend.dll: Detoured EntryPoint().\n");
        }
        else {
            printf("extend.dll: Error detouring EntryPoint(): %d\n", error);
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        // Detach functions found from the export table.
        if (TrueTarget != NULL) {
            DetourDetach(&(PVOID&)TrueTarget, (PVOID)Extend);
        }

        // Detach functions found from debug symbols.
        if (TrueHidden != NULL) {
            DetourDetach(&(PVOID&)TrueHidden, (PVOID)Intern);
        }

        // Detach the entry point.
        DetourDetach(&(PVOID&)TrueEntryPoint, ExtendEntryPoint);
        error = DetourTransactionCommit();

        printf("extend.dll: Removed Target() detours (%d), %d/%d calls.\n",
               error, nExtends, nInterns);

        fflush(stdout);
    }
    return TRUE;
}
//
///////////////////////////////////////////////////////////////// End of File.
