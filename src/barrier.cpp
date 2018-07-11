#define _CRT_STDIO_ARBITRARY_WIDE_SPECIFIERS 1

#pragma warning(disable:4068) // unknown pragma (suppress)

#if _MSC_VER >= 1900
#pragma warning(push)
#pragma warning(disable:4091) // empty typedef
#endif

#define _ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE 1
#include <windows.h>
#include <aux_ulib.h>
#if (_MSC_VER < 1310)
#else
#pragma warning(push)
#if _MSC_VER > 1400
#pragma warning(disable:6102 6103) // /analyze warnings
#endif
#include <strsafe.h>
#pragma warning(pop)
#endif

// #define DETOUR_DEBUG 1
#define DETOURS_INTERNAL
#include "detours.h"

#if DETOURS_VERSION != 0x4c0c1   // 0xMAJORcMINORcPATCH
#error detours.h version mismatch
#endif

#if _MSC_VER >= 1900
#pragma warning(pop)
#endif

// allocate at DLL Entry
HANDLE              hCoreHookHeap = NULL;

BARRIER_UNIT         Unit;


void RtlInitializeLock(RTL_SPIN_LOCK* OutLock)
{
    RtlZeroMemory(OutLock, sizeof(RTL_SPIN_LOCK));

    InitializeCriticalSection(&OutLock->Lock);
}

void RtlAcquireLock(RTL_SPIN_LOCK* InLock)
{
    EnterCriticalSection(&InLock->Lock);

    ASSERT2(!InLock->IsOwned,L"barrier.cpp - !InLock->IsOwned");

    InLock->IsOwned = TRUE;
}

void RtlReleaseLock(RTL_SPIN_LOCK* InLock)
{
    ASSERT2(InLock->IsOwned,L"barrier.cpp - InLock->IsOwned");

    InLock->IsOwned = FALSE;

    LeaveCriticalSection(&InLock->Lock);
}

void RtlDeleteLock(RTL_SPIN_LOCK* InLock)
{
    ASSERT2(!InLock->IsOwned,L"barrier.cpp - InLock->IsOwned");

    DeleteCriticalSection(&InLock->Lock);
}

void RtlSleep(ULONG InTimeout)
{
    Sleep(InTimeout);
}


void RtlCopyMemory(
            PVOID InDest,
            PVOID InSource,
            ULONG InByteCount)
{
    ULONG       Index;
    UCHAR*      Dest = (UCHAR*)InDest;
    UCHAR*      Src = (UCHAR*)InSource;

    for(Index = 0; Index < InByteCount; Index++)
    {
        *Dest = *Src;

        Dest++;
        Src++;
    }
}

void* RtlAllocateMemory(BOOL InZeroMemory, ULONG InSize)
{
    void*       Result = 
#ifdef _DEBUG
		HeapAlloc(hCoreHookHeap, 0, InSize);
#else
        HeapAlloc(hCoreHookHeap, 0, InSize);
#endif

    if(InZeroMemory && (Result != NULL))
        RtlZeroMemory(Result, InSize);

    return Result;
}


#ifndef _DEBUG
    #pragma optimize ("", off) // suppress _memset
#endif
void RtlZeroMemory(
            PVOID InTarget,
            ULONG InByteCount)
{
    ULONG           Index;
    UCHAR*          Target = (UCHAR*)InTarget;

    for(Index = 0; Index < InByteCount; Index++)
    {
        *Target = 0;

        Target++;
    }
}
#ifndef _DEBUG
    #pragma optimize ("", on) 
#endif


LONG RtlProtectMemory(void* InPointer, ULONG InSize, ULONG InNewProtection)
{
    DWORD       OldProtect;
    LONG        NtStatus;

    if(!VirtualProtect(InPointer, InSize, InNewProtection, &OldProtect)) {
        THROW(STATUS_INVALID_PARAMETER, (WCHAR*)L"Unable to make memory executable.")
    }
    else {
        return 0;
    }
THROW_OUTRO:
//FINALLY_OUTRO:
    return NtStatus;
}

void RtlFreeMemory(void* InPointer)
{
	ASSERT2(InPointer != NULL,L"barrier.cpp - InPointer != NULL");

#ifdef _DEBUG
    //free(InPointer);
#else
    HeapFree(hCoreHookHeap, 0, InPointer);
#endif
}

LONG RtlInterlockedIncrement(LONG* RefValue)
{
    return InterlockedIncrement(RefValue);
}

BOOL RtlIsValidPointer(PVOID InPtr, ULONG InSize)
{
    if((InPtr == NULL) || (InPtr == (PVOID)~0))
        return FALSE;

    ASSERT2(!IsBadReadPtr(InPtr, InSize),L"barrier.cpp - !IsBadReadPtr(InPtr, InSize)");

    return TRUE;
}

static PWCHAR           LastError = (PWCHAR)L"";
static ULONG            LastErrorCode = 0;

void RtlSetLastError(LONG InCode, LONG InNtStatus, WCHAR* InMessage)
{
    LastErrorCode = InCode;

    if(InMessage == NULL)
        LastError = (PWCHAR)L"";
    else
    {
        if(InNtStatus == 0) {

        }
#if _DEBUG
        LastErrorCode = InNtStatus;
#endif
        LastError = (PWCHAR)InMessage;
    }
}
void RtlAssert(BOOL InAssert,LPCWSTR lpMessageText)
{
    if(InAssert)
        return;

#ifdef _DEBUG
    DebugBreak();
#endif
    FatalAppExitW(0, lpMessageText);
}


LONG LhSetGlobalInclusiveACL(
            ULONG* InThreadIdList,
            ULONG InThreadCount)
{
/*
Description:

    Sets an inclusive global ACL based on the given thread ID list.
    
Parameters:
    - InThreadIdList
        An array of thread IDs. If you specific zero for an entry in this array,
        it will be automatically replaced with the calling thread ID.

    - InThreadCount
        The count of entries listed in the thread ID list. This value must not exceed
        MAX_ACE_COUNT! 
*/
    return LhSetACL(LhBarrierGetAcl(), FALSE, InThreadIdList, InThreadCount);
}

LONG LhSetGlobalExclusiveACL(
            ULONG* InThreadIdList,
            ULONG InThreadCount)
{
/*
Description:

    Sets an exclusive global ACL based on the given thread ID list.
    
Parameters:
    - InThreadIdList
        An array of thread IDs. If you specific zero for an entry in this array,
        it will be automatically replaced with the calling thread ID.

    - InThreadCount
        The count of entries listed in the thread ID list. This value must not exceed
        MAX_ACE_COUNT! 
*/
    return LhSetACL(LhBarrierGetAcl(), TRUE, InThreadIdList, InThreadCount);
}

BOOL LhIsValidHandle(
            TRACED_HOOK_HANDLE InTracedHandle,
            PLOCAL_HOOK_INFO* OutHandle)
{
/*
Description:

    A handle is considered to be valid, if the whole structure
    points to valid memory AND the signature is valid AND the
    hook is installed!

*/
    if(!IsValidPointer(InTracedHandle, sizeof(HOOK_TRACE_INFO)))
        return FALSE;

    if(OutHandle != NULL)
        *OutHandle = InTracedHandle->Link;

    return TRUE;
}
LONG LhSetACL(
            HOOK_ACL* InAcl,
            BOOL InIsExclusive,
            ULONG* InThreadIdList,
            ULONG InThreadCount)
{
/*
Description:

    This method is used internally to provide a generic interface to
    either the global or local hook ACLs.
    
Parameters:
    - InAcl
        NULL if you want to set the global ACL.
        Any LOCAL_HOOK_INFO::LocalACL to set the hook specific ACL.

    - InIsExclusive
        TRUE if all listed thread shall be excluded from interception,
        FALSE otherwise

    - InThreadIdList
        An array of thread IDs. If you specific zero for an entry in this array,
        it will be automatically replaced with the calling thread ID.

    - InThreadCount
        The count of entries listed in the thread ID list. This value must not exceed
        MAX_ACE_COUNT! 
*/

    ULONG           Index;

    ASSERT2(IsValidPointer(InAcl, sizeof(HOOK_ACL)),L"barrier.cpp - IsValidPointer(InAcl, sizeof(HOOK_ACL))");

    if(InThreadCount > MAX_ACE_COUNT)
        return -2;

    if(!IsValidPointer(InThreadIdList, InThreadCount * sizeof(ULONG)))
        return -1;

    for(Index = 0; Index < InThreadCount; Index++)
    {
        if(InThreadIdList[Index] == 0)
            InThreadIdList[Index] = GetCurrentThreadId();
    }
	DWORD dwOld;
	if (VirtualProtect(InAcl, sizeof(HOOK_ACL), PAGE_READWRITE, &dwOld)) {
		// set ACL...
		InAcl->IsExclusive = InIsExclusive;
		InAcl->Count = InThreadCount;

		RtlCopyMemory(InAcl->Entries, InThreadIdList, InThreadCount * sizeof(ULONG));

		DWORD dwOld2;
		VirtualProtect(InAcl, sizeof(HOOK_ACL), dwOld, &dwOld2);
	}
    else {
        return -3;
    }

    return 0;
}

HOOK_ACL* LhBarrierGetAcl()
{
     return &Unit.GlobalACL;
}

LONG LhBarrierProcessAttach()
{
/*
Description:

    Will be called on DLL load and initializes all barrier structures.
*/
	RtlZeroMemory(&Unit, sizeof(Unit));

	// globally accept all threads...
	Unit.GlobalACL.IsExclusive = TRUE;

	// allocate private heap
    RtlInitializeLock(&Unit.TLS.ThreadSafe);

    Unit.IsInitialized =  AuxUlibInitialize() ? TRUE: FALSE;;

    hCoreHookHeap = HeapCreate(0, 0, 0);

	return 0;
}


BOOL TlsGetCurrentValue(
            THREAD_LOCAL_STORAGE* InTls,                
            THREAD_RUNTIME_INFO** OutValue)
{
/*
Description:

    Queries the THREAD_RUNTIME_INFO for the calling thread.
    The caller shall previously be added to the storage by
    using TlsAddCurrentThread().

Parameters:

    - InTls

        The storage where the caller is registered.

    - OutValue

        Is filled with a pointer to the caller's private storage entry.

Returns:

    FALSE if the caller was not registered in the storage, TRUE otherwise.
*/
	ULONG		CurrentId = (ULONG)GetCurrentThreadId();

    LONG        Index;

	for(Index = 0; Index < MAX_THREAD_COUNT; Index++)
	{
		if(InTls->IdList[Index] == CurrentId)
		{
			*OutValue = &InTls->Entries[Index];

			return TRUE;
		}
	}

	return FALSE;
}
BOOL TlsAddCurrentThread(THREAD_LOCAL_STORAGE* InTls)
{
/*
Description:

    Tries to reserve a THREAD_RUNTIME_INFO entry for the calling thread.
    On success it may call TlsGetCurrentValue() to query a pointer to
    its private entry.

    This is a replacement for the Windows Thread Local Storage which seems
    to cause trouble when using it in Explorer.EXE for example.

    No parameter validation (for performance reasons).

    This method will raise an assertion if the thread was already added
    to the storage!

Parameters:
    - InTls

        The thread local storage to allocate from.

Returns:

    TRUE on success, FALSE otherwise.
*/
	ULONG		CurrentId = (ULONG)GetCurrentThreadId();

	LONG		Index = -1;
    LONG		i;

    RtlAcquireLock(&InTls->ThreadSafe);

    // select Index AND check whether thread is already registered.
	for(i = 0; i < MAX_THREAD_COUNT; i++)
	{
		if((InTls->IdList[i] == 0) && (Index == -1))
			Index = i;
		
		ASSERT2(InTls->IdList[i] != CurrentId,L"barrier.cpp - InTls->IdList[i] != CurrentId");
	}

	if(Index == -1)
	{
		RtlReleaseLock(&InTls->ThreadSafe);

		return FALSE;
	}

	InTls->IdList[Index] = CurrentId;
	RtlZeroMemory(&InTls->Entries[Index], sizeof(THREAD_RUNTIME_INFO));
	
	RtlReleaseLock(&InTls->ThreadSafe);

	return TRUE;
}

void TlsRemoveCurrentThread(THREAD_LOCAL_STORAGE* InTls)
{
/*
Description:

    Removes the caller from the local storage. If the caller
    is already removed, the method will do nothing.

Parameters:

    - InTls

        The storage from which the caller should be removed.
*/
	ULONG		    CurrentId = (ULONG)GetCurrentThreadId();
    ULONG           Index;

    RtlAcquireLock(&InTls->ThreadSafe);

	for(Index = 0; Index < MAX_THREAD_COUNT; Index++)
	{
		if(InTls->IdList[Index] == CurrentId)
		{
			InTls->IdList[Index] = 0;

			RtlZeroMemory(&InTls->Entries[Index], sizeof(THREAD_RUNTIME_INFO));
		}
	}

	RtlReleaseLock(&InTls->ThreadSafe);
}

void LhBarrierProcessDetach()
{
/*
Description:

    Will be called on DLL unload.
*/
	ULONG			Index;

	RtlDeleteLock(&Unit.TLS.ThreadSafe);

	// release thread specific resources
	for(Index = 0; Index < MAX_THREAD_COUNT; Index++)
	{
		if(Unit.TLS.Entries[Index].Entries != NULL)
			RtlFreeMemory(Unit.TLS.Entries[Index].Entries);
	}

	RtlZeroMemory(&Unit, sizeof(Unit));

    HeapDestroy(hCoreHookHeap);    
}

void LhBarrierThreadDetach()
{
/*
Description:

    Will be called on thread termination and cleans up the TLS.
*/
	LPTHREAD_RUNTIME_INFO		Info;

	if(TlsGetCurrentValue(&Unit.TLS, &Info))
	{
		if(Info->Entries != NULL)
			RtlFreeMemory(Info->Entries);

		Info->Entries = NULL;
	}

	TlsRemoveCurrentThread(&Unit.TLS);
}

RTL_SPIN_LOCK               GlobalHookLock;

void LhCriticalInitialize()
{
/*
Description:
    
    Fail safe initialization of global hooking structures...
*/

    RtlInitializeLock(&GlobalHookLock);
}

void LhCriticalFinalize()
{
/*
Description:

    Will be called in the DLL_PROCESS_DETACH event and just uninstalls
    all hooks. If it is possible also their memory is released. 
*/
	RtlDeleteLock(&GlobalHookLock);
}

BOOL IsLoaderLock()
{
/*
Returns:

    TRUE if the current thread hols the OS loader lock, or the library was not initialized
    properly. In both cases a hook handler should not be executed!

    FALSE if it is safe to execute the hook handler.

*/
	BOOL     IsLoaderLock = FALSE;

	return (!AuxUlibIsDLLSynchronizationHeld(&IsLoaderLock) || IsLoaderLock || !Unit.IsInitialized);
}


BOOL AcquireSelfProtection()
{
/*
Description:

    To provide more convenience for writing the TDB, this self protection
    will disable ALL hooks for the current thread until ReleaseSelfProtection() 
    is called. This allows one to call any API during TDB initialization
    without being intercepted...

Returns:

    TRUE if the caller's runtime info has been locked down.

    FALSE if the caller's runtime info already has been locked down
    or is not available. The hook handler should not be executed in
    this case!

*/
	LPTHREAD_RUNTIME_INFO		Runtime = NULL;

	if(!TlsGetCurrentValue(&Unit.TLS, &Runtime) || Runtime->IsProtected)
		return FALSE;

	Runtime->IsProtected = TRUE;

	return TRUE;
}

void ReleaseSelfProtection()
{
/*
Description:

    Exists the TDB self protection. Refer to AcquireSelfProtection() for more
    information.

    An assertion is raised if the caller has not owned the self protection.
*/
	LPTHREAD_RUNTIME_INFO		Runtime = NULL;

	ASSERT2(TlsGetCurrentValue(&Unit.TLS, &Runtime) && Runtime->IsProtected,L"barrier.c - TlsGetCurrentValue(&Unit.TLS, &Runtime) && Runtime->IsProtected");

	Runtime->IsProtected = FALSE;
}



BOOL ACLContains(
	HOOK_ACL* InACL,
	ULONG InCheckID)
{
/*
Returns:

    TRUE if the given ACL contains the given ID, FALSE otherwise.
*/
    ULONG           Index;

	for(Index = 0; Index < InACL->Count; Index++)
	{
		if(InACL->Entries[Index] == InCheckID)
			return TRUE;
	}

	return FALSE;
}


BOOL IsThreadIntercepted(
	HOOK_ACL* LocalACL, 
	ULONG InThreadID)
{
/*
Description:

    Please refer to LhIsThreadIntercepted() for more information.

Returns:

    TRUE if the given thread is intercepted by the global AND local ACL,
    FALSE otherwise.
*/
	ULONG				CheckID;

	if(InThreadID == 0)
		CheckID = GetCurrentThreadId();
	else
		CheckID = InThreadID;

	if(ACLContains(&Unit.GlobalACL, CheckID))
	{
		if(ACLContains(LocalACL, CheckID))
		{
			if(LocalACL->IsExclusive)
				return FALSE;
		}
		else
		{
			if(!LocalACL->IsExclusive)
				return FALSE;
		}

		return !Unit.GlobalACL.IsExclusive;
	}
	else
	{
		if(ACLContains(LocalACL, CheckID))
		{
			if(LocalACL->IsExclusive)
				return FALSE;
		}
		else
		{
			if(!LocalACL->IsExclusive)
				return FALSE;
		}

		return Unit.GlobalACL.IsExclusive;
	}
}

LONG LhBarrierGetCallback(PVOID* OutValue)
{
/*
Description:

    Is expected to be called inside a hook handler. Otherwise it
    will fail with STATUS_NOT_SUPPORTED. The method retrieves
    the callback initially passed to the related LhInstallHook()
    call.

*/
    LONG            NtStatus;
	LPTHREAD_RUNTIME_INFO       Runtime;

    if(!IsValidPointer(OutValue, sizeof(PVOID)))
        THROW(STATUS_INVALID_PARAMETER, (PWCHAR)L"Invalid result storage specified.");

	if(!TlsGetCurrentValue(&Unit.TLS, &Runtime))
        THROW(-1, (PWCHAR)("The caller is not inside a hook handler."));

	if(Runtime->Current != NULL)
		*OutValue = Runtime->Callback;
	else
		THROW(-1, (PWCHAR)L"The caller is not inside a hook handler.");

    RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
    return NtStatus;
}

LONG LhInstallHook(
            void* InEntryPoint,
            void* InHookProc,
            void* InCallback,
            TRACED_HOOK_HANDLE OutHandle)
{
/*
Description:

    Installs a hook at the given entry point, redirecting all
    calls to the given hooking method. The returned handle will
    either be released on library unloading or explicitly through
    LhUninstallHook() or LhUninstallAllHooks().

Parameters:

    - InEntryPoint

        An entry point to hook. Not all entry points are hookable. In such
        a case STATUS_NOT_SUPPORTED will be returned.

    - InHookProc

        The method that should be called instead of the given entry point.
        Please note that calling convention, parameter count and return value
        shall match EXACTLY!

    - InCallback

        An uninterpreted callback later available through
        LhBarrierGetCallback().

    - OutPHandle

        The memory portion supplied by *OutHandle is expected to be preallocated
        by the caller. This structure is then filled by the method on success and
        must stay valid for hook-life time. Only if you explicitly call one of
        the hook uninstallation APIs, you can safely release the handle memory.

Returns:

    STATUS_NO_MEMORY
    
        Unable to allocate memory around the target entry point.
    
    STATUS_NOT_SUPPORTED
    
        The target entry point contains unsupported instructions.
    
    STATUS_INSUFFICIENT_RESOURCES
    
        The limit of MAX_HOOK_COUNT simultaneous hooks was reached.
    
*/

    LONG error = -1;

    error = DetourTransactionBegin();

    error = DetourUpdateThread(GetCurrentThread());

    error = DetourAttach(&(PVOID&)InEntryPoint, InHookProc);

    error = DetourTransactionCommit();

	TRACED_HOOK_HANDLE handle = (TRACED_HOOK_HANDLE)DetourGetHookHandleForFunction(&(PVOID&)InEntryPoint);

    if(OutHandle != NULL && handle != NULL) {
        OutHandle->Link = handle->Link;
    }
    if(InCallback != NULL) {
        error = DetourSetCallbackForLocalHook(&(PVOID&)InEntryPoint, InCallback);        
    }
    return error;
}

