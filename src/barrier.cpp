#define _CRT_STDIO_ARBITRARY_WIDE_SPECIFIERS 1

#pragma warning(disable:4068) // unknown pragma (suppress)

#if _MSC_VER >= 1900
#pragma warning(push)
#pragma warning(disable:4091) // empty typedef
#endif

#define _ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE 1
#include <windows.h>
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
HANDLE              hEasyHookHeap = NULL;

typedef struct _RTL_SPIN_LOCK_
{
    CRITICAL_SECTION        Lock;
    BOOL                 IsOwned;
}RTL_SPIN_LOCK;


typedef struct _RUNTIME_INFO_
{
	// "true" if the current thread is within the related hook handler
	BOOL            IsExecuting;
	// the hook this information entry belongs to... This allows a per thread and hook storage!
	DWORD           HLSIdent;
	// the return address of the current thread's hook handler...
	void*           RetAddress;
    // the address of the return address of the current thread's hook handler...
	void**          AddrOfRetAddr;
}RUNTIME_INFO;

typedef struct _THREAD_RUNTIME_INFO_
{
	RUNTIME_INFO*		Entries;
	RUNTIME_INFO*		Current;
	void*				Callback;
	BOOL				IsProtected;
}THREAD_RUNTIME_INFO, *LPTHREAD_RUNTIME_INFO;

typedef struct _THREAD_LOCAL_STORAGE_
{
    THREAD_RUNTIME_INFO		Entries[MAX_THREAD_COUNT];
    DWORD					IdList[MAX_THREAD_COUNT];
    RTL_SPIN_LOCK			ThreadSafe;
}THREAD_LOCAL_STORAGE;

typedef struct _BARRIER_UNIT_
{
	HOOK_ACL				GlobalACL;
	BOOL					IsInitialized;
	THREAD_LOCAL_STORAGE	TLS;
}BARRIER_UNIT;

static BARRIER_UNIT         Unit;

void RtlInitializeLock(RTL_SPIN_LOCK* InLock);

void RtlAcquireLock(RTL_SPIN_LOCK* InLock);

void RtlReleaseLock(RTL_SPIN_LOCK* InLock);

void RtlDeleteLock(RTL_SPIN_LOCK* InLock);

void RtlSleep(ULONG InTimeout);

void* RtlAllocateMemory(
            BOOL InZeroMemory, 
            ULONG InSize);

void RtlFreeMemory(void* InPointer);

#undef RtlCopyMemory
void RtlCopyMemory(
            PVOID InDest,
            PVOID InSource,
            ULONG InByteCount);

#undef RtlMoveMemory
BOOL RtlMoveMemory(
            PVOID InDest,
            PVOID InSource,
            ULONG InByteCount);

#undef RtlZeroMemory
void RtlZeroMemory(
            PVOID InTarget,
            ULONG InByteCount);

void RtlInitializeLock(RTL_SPIN_LOCK* OutLock)
{
    RtlZeroMemory(OutLock, sizeof(RTL_SPIN_LOCK));

    InitializeCriticalSection(&OutLock->Lock);
}

void RtlAcquireLock(RTL_SPIN_LOCK* InLock)
{
    EnterCriticalSection(&InLock->Lock);

    ASSERT(!InLock->IsOwned,L"memory.c - !InLock->IsOwned");

    InLock->IsOwned = TRUE;
}

void RtlReleaseLock(RTL_SPIN_LOCK* InLock)
{
    ASSERT(InLock->IsOwned,L"memory.c - InLock->IsOwned");

    InLock->IsOwned = FALSE;

    LeaveCriticalSection(&InLock->Lock);
}

void RtlDeleteLock(RTL_SPIN_LOCK* InLock)
{
    ASSERT(!InLock->IsOwned,L"memory.c - InLock->IsOwned");

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

BOOL RtlMoveMemory(
            PVOID InDest,
            PVOID InSource,
            ULONG InByteCount)
{
    PVOID       Buffer = RtlAllocateMemory(FALSE, InByteCount);

    if(Buffer == NULL)
        return FALSE;

    RtlCopyMemory(Buffer, InSource, InByteCount);
    RtlCopyMemory(InDest, Buffer, InByteCount);

    RtlFreeMemory(Buffer);
    return TRUE;
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


void* RtlAllocateMemory(BOOL InZeroMemory, ULONG InSize)
{
    void*       Result = 
#ifdef _DEBUG
        malloc(InSize);
#else
        HeapAlloc(hEasyHookHeap, 0, InSize);
#endif

    if(InZeroMemory && (Result != NULL))
        RtlZeroMemory(Result, InSize);

    return Result;
}

LONG RtlProtectMemory(void* InPointer, ULONG InSize, ULONG InNewProtection)
{
    DWORD       OldProtect;
    LONG        NtStatus;

    if(!VirtualProtect(InPointer, InSize, InNewProtection, &OldProtect)) {
        THROW(STATUS_INVALID_PARAMETER, L"Unable to make memory executable.")
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
	ASSERT(InPointer != NULL,L"InPointer != NULL");

#ifdef _DEBUG
    free(InPointer);
#else
    HeapFree(hEasyHookHeap, 0, InPointer);
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

    ASSERT(!IsBadReadPtr(InPtr, InSize),L"memory.c - !IsBadReadPtr(InPtr, InSize)");

    return TRUE;
}
static PWCHAR           LastError = L"";
static ULONG            LastErrorCode = 0;

void RtlSetLastError(LONG InCode, LONG InNtStatus, WCHAR* InMessage)
{
    LastErrorCode = InCode;

    if(InMessage == NULL)
        LastError = L"";
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

    ASSERT(IsValidPointer(InAcl, sizeof(HOOK_ACL)),L"acl.c - IsValidPointer(InAcl, sizeof(HOOK_ACL))");

    if(InThreadCount > MAX_ACE_COUNT)
        return -2;

    if(!IsValidPointer(InThreadIdList, InThreadCount * sizeof(ULONG)))
        return -1;

    for(Index = 0; Index < InThreadCount; Index++)
    {
        if(InThreadIdList[Index] == 0)
            InThreadIdList[Index] = GetCurrentThreadId();
    }

    // set ACL...
    InAcl->IsExclusive = InIsExclusive;
    InAcl->Count = InThreadCount;

    RtlCopyMemory(InAcl->Entries, InThreadIdList, InThreadCount * sizeof(ULONG));

    return 0;
}

HOOK_ACL* LhBarrierGetAcl()
{
     return &Unit.GlobalACL;
}