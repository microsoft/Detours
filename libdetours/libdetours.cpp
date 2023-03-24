#include <windows.h>

BOOL WINAPI DllMain(
    HINSTANCE hinst, // handle to DLL module
    DWORD reason,    // reason for calling function, DLL_*
    LPVOID reserved) // reserved
{
    UNREFERENCED_PARAMETER(hinst);
    UNREFERENCED_PARAMETER(reserved);
    // Perform actions based on the reason for calling.
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:

        if (reserved != nullptr)
        {
            break; // do not do cleanup if process termination scenario
        }

        // Perform any necessary cleanup.
        break;
    }
    return TRUE; // Successful DLL_PROCESS_ATTACH.
}
