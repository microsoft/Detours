#include <windows.h>
#include <detours.h>

int main()
{
    if (DetourTransactionBegin() != NO_ERROR)
    {
        return 1;
    }

    return DetourTransactionAbort() == NO_ERROR ? 0 : 1;
}
