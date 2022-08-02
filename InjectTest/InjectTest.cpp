// InjectTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include "..\include\detours.h"
#pragma comment(lib, "..\\lib.X64\\detours.lib") //TODO:Implement this another way in a real build system and properly get the right library for the build
#pragma comment(lib, "psapi")
EXTERN_C_START
bool
__stdcall InjectThread
(
    HANDLE hProcess,
    LPTHREAD_START_ROUTINE entry,
    PBYTE param,
    SIZE_T paramSize
)
{
#if _M_IX86
    bool const isWow64 = IsWow64(hProcess);
#else // !_M_IX86
    static constexpr bool isWow64 = false;
#endif // !_M_IX86
    void* allocatedMemory = NULL;
    if (param && paramSize > 0)
    {
        allocatedMemory = VirtualAllocEx(hProcess, NULL, paramSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (allocatedMemory == NULL) return false;
        SIZE_T bytesWritten;
        if (!WriteProcessMemory(hProcess, allocatedMemory, param, paramSize, &bytesWritten))
        {
            VirtualFreeEx(hProcess, allocatedMemory, paramSize, MEM_RELEASE);
            return false;
        }
    }
    HANDLE hThread = CreateRemoteThread(hProcess,
        NULL,    // lpThreadAttributes
        0,       // dwStackSize
        entry,   // lpStartAddress
        allocatedMemory,    // lpParameter
        0,       // dwCreationFlags
        NULL     // threadId
    );

    if (hThread == NULL)
    {
        //TODO:Could not create remote thread
        return false;
    }

    ULONG st = WaitForSingleObject(hThread, 20000); //arbitary wait time for testing

    CloseHandle(hThread);

    if (st == WAIT_TIMEOUT)
    {

        //TODO:Wait timed out so the thread didn't complete in the allotted time
        return false;
    }
    else if (st != WAIT_OBJECT_0)
    {
        //TODO:Wait for remote thread failed. 
        return false;
    }
    //The thread finished
    return true;
}
BOOL FindKernelbaseInProcess(HANDLE hProcess, HMODULE* pHKB)
{
    SIZE_T handleCount = 4000000; //Using a huge buffer here but calling the function in a loop while there is more data needed would be a better production strategy, perhaps starting with a more reasonable sized buffer
    HMODULE* handles = (HMODULE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleCount * sizeof(HMODULE));
    DWORD sizeNeeded;
    if(!handles) return FALSE;
    if (!EnumProcessModulesEx(hProcess, handles, handleCount * sizeof(HMODULE), &sizeNeeded, LIST_MODULES_ALL))
    {
        HeapFree(GetProcessHeap(), 0, handles);
        return FALSE;
    }
    MODULEINFO mi = {};
    wchar_t moduleName[MAX_PATH];
    for (DWORD index = 0; index < sizeNeeded / sizeof(HMODULE); index++)
    {
        HMODULE hMod = handles[index];
        if (GetModuleBaseName(hProcess, hMod, moduleName, _countof(moduleName)))
        {
            OutputDebugString(moduleName);
            OutputDebugString(L"\n");
            if (CompareStringOrdinal(L"kernelbase.dll", lstrlenW(L"kernelbase.dll"), moduleName, lstrlenW(moduleName), TRUE) == CSTR_EQUAL)
            {
                //found kernelbase
                if (GetModuleInformation(hProcess, hMod, &mi, sizeof(mi)))
                {
                    *pHKB = (HMODULE)mi.lpBaseOfDll;
                    HeapFree(GetProcessHeap(), 0, handles);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}
EXTERN_C_END

int main()
{
    //Injection Options
    //1.  For Gui processes, SetWindowsHookEx can be used; the library can then pin itself GetModuleEx and GET_MODULE_HANDLE_EX_FLAG_PIN once loaded and release the hook
    //2.  Createremotethread can be called in another process to load a library of the same bitness into that process
    //3.  Createremotethread can be called in another process to activate executable code that was placed there without loading a library (that code can either just be all that is placed or it can load binaries)
    //4.  The import table of the exe can be modified before the process start continues so that the exe has a required import on the dll which you want to load
    //5.  4 can be done by calling/controlling (perhaps through hooking) CreateProcess* calls, make processes suspended, patching the exe, and then letting it resume (this is done by Deoutrs...well, the helper functions just do the Create part but they could easily be expanded
    //6.  4 can be done by using kernel callbacks combined with user mode code - https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine will tell you when a process is being created
    //7.  4 can be done through kernel callbacks combined with user mode code and https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pload_image_notify_routine
    DWORD pid;
    std::cout << "This is a basic test app for injecting the basic dll.  You'll want to verify you are injecting from/to the right architectures with the desired binary to cover all scenarios.  Rundll32 as a helper process is one way to accomplish this but really any way that your dev team is comfortable with will work.  See creatwth.cpp to see how it does process creation while injecting dlls.\n";
    std::cout << "Please enter process id to inject this to:     ";
    std::cin >> pid;
    const char* dllName = "C:\\Users\\chrlew\\source\\repos\\Detours\\vc\\x64\\DebugMDd\\DetourOutputDebugString.dll"; //TODO:this should be somewhere it can be found and a full path is a much better idea than just the module name in production code; for this sample/test, I put the path on my hard drive
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); //TODO:One can be more specific with necessary access
    if (hProcess)
    {
        if (!DetourUpdateProcessWithDll(hProcess, &dllName, 1)) //This isn't doing anything on its own, but if you do this with a suspended process, it'll cause the loader to load the dll you want without injecting a thread by sticking the dll into the import table of the exe
        {
            std::cout << "Updating process failed!" << std::endl;
        }
        else
        {
            //Find loadlibrary in process; this works if everything is the same architecture, otherwise you'd want to use ReadProcessMemory to read the PE headers to find this remotely
            //This requires the architecture matching the target process and is something that one would want to wrap with helper dlls or processes (e.g. inject ARM64 from ARM64, ARM32 from ARM32, x86 to x86,  x64 to x64 )
            // https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2 will help with this from user mode, in Windows 11 there is also a kernel mode API available for that information (but not Windows 10 - the info obviously exists there but there isn't a supported API to access it from kernel mode until Windows 11 - walking the address manually to figure it out also is possible but I'd recommend avoiding that in favor of the APIs)
            //This could also be done through an APC I believe if one preferred doing the injection from kernel mode (it may be easier to use the Nt version of the function though)
            HMODULE hModKB = GetModuleHandleA("kernelbase.dll");
            auto procAddr = GetProcAddress(hModKB, "LoadLibraryA");
            HMODULE remoteHModKB;
            if (FindKernelbaseInProcess(hProcess, &remoteHModKB))
            {
                LPTHREAD_START_ROUTINE routine = (LPTHREAD_START_ROUTINE)(remoteHModKB - hModKB + (SIZE_T)(void*)procAddr);
                if (InjectThread(hProcess, routine, (PBYTE)dllName, lstrlenA(dllName)))
                {
                    std::cout << "Thread injected" << std::endl; //One would probably want to get the exit code of the thread and make sure it returned non-zero for logging purposes and to know that the library didn't load
                }
            }
            else
                std::cout << "Couldn't find kernelbase in the process" << std::endl;
        }
    }
    else std::cout << "OpenProcessFailed" << std::endl;


}
