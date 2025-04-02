//////////////////////////////////////////////////////////////////////////////
//
//  Unit Tests for Detours Module API (test_module_api.cpp of unittests.exe)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#include "catch.hpp"
#include "windows.h"

#define DETOURS_INTERNAL

#include "detours.h"
#include "corruptor.h"
#include "payload.h"
#include "process_helpers.h"

// Expose the image base of the current module for test assertions.
//
extern "C" IMAGE_DOS_HEADER __ImageBase;

// Expose default module entry point for test assertions.
//
extern "C" int mainCRTStartup();

// Dummy function pointer used for tests.
//
void NoopFunction() { }

#include <Windows.h>

#if defined(_ARM64EC_)
inline bool
StdFFSMatch(
    unsigned __int64 x64Address,
    unsigned __int64 EcAddress
    )
{
    unsigned __int64 FFSpart1;
    unsigned short FFSpart2;
    unsigned __int64 EcAddr;
    int JmpOffset;

    //
    // A standard fast-forward sequence follows this pattern
    //
    //   488bc4          mov     rax,rsp
    //   48895820        mov     qword ptr [rax+20h],rbx
    //   55              push    rbp
    //   5d              pop     rbp
    //   e952df1600      jmp     ntdll!_swprintf (00000001`80178760)
    //
    // See https://learn.microsoft.com/en-us/cpp/cpp/hybrid-patchable?view=msvc-170 for details.
    //

    if (x64Address % 16 != 0)
    {
        //
        // All standard FFS are 16-byte aligned guaranteed by compiler
        //

        return false;
    }

    if (RtlIsEcCode(x64Address))
    {
        //
        // Arm64EC code is never a standard FFS
        //

        return false;
    }

    __try
    {
        FFSpart1 = ReadULong64NoFence((ULONG64*)x64Address);
        FFSpart2 = ReadUShortNoFence((USHORT*)(x64Address + 8));
        JmpOffset = ReadULongNoFence((ULONG*)(x64Address + 10));
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }

    if (FFSpart1 == 0x5520588948c48b48 && FFSpart2 == 0xe95d)
    {

        EcAddr = (ULONG_PTR)((LONG_PTR)x64Address + 14 + JmpOffset);
        if (!RtlIsEcCode(EcAddr))
        {
            return false;
        }

        if (EcAddress != EcAddr)
        {
            return false;
        }

        return true;
    }

    return false;
}
#endif

bool EquivalentFunctions(void* a, void* b)
{
    if (a == b)
    {
        return true;
    }

    // TODO: Remove Arm64EC-specific FFS matching logic when address taken operator
    //       inconsistency in Arm64EC MSVC is fixed.
    //       See https://developercommunity.visualstudio.com/t/Functions-dllimported-from-arm64ec-dlls/10670642
#if defined(_ARM64EC_)
    if (StdFFSMatch(reinterpret_cast<unsigned __int64>(a), reinterpret_cast<unsigned __int64>(b)) ||
        StdFFSMatch(reinterpret_cast<unsigned __int64>(b), reinterpret_cast<unsigned __int64>(a)))
    {
        return true;
    }
#endif

    return false;
}

TEST_CASE("DetourLoadImageHlp", "[module]")
{
    SECTION("Passing own function, results in own HMODULE")
    {
        auto info = DetourLoadImageHlp();

        REQUIRE( info != nullptr );
        REQUIRE( info->hDbgHelp != NULL);
        REQUIRE( info->pfImagehlpApiVersionEx != nullptr );
        REQUIRE( info->pfSymInitialize != nullptr );
        REQUIRE( info->pfSymSetOptions != nullptr );
        REQUIRE( info->pfSymGetOptions != nullptr );
        REQUIRE( info->pfSymLoadModule64 != nullptr );
        REQUIRE( info->pfSymGetModuleInfo64 != nullptr );
        REQUIRE( info->pfSymFromName != nullptr );
    }
}

TEST_CASE("DetourFindFunction", "[module]")
{
    SECTION("Passing nullptr for all parameters, results in nullptr")
    {
        SetLastError(NO_ERROR);

        auto func = DetourFindFunction(nullptr, nullptr);

        REQUIRE( GetLastError() == ERROR_INVALID_PARAMETER );
        REQUIRE( func == nullptr );
    }

    SECTION("Passing nullptr for function, results in nullptr")
    {
        SetLastError(NO_ERROR);

        auto func = DetourFindFunction("ntdll.dll", nullptr);

        REQUIRE( GetLastError() == ERROR_INVALID_PARAMETER );
        REQUIRE( func == nullptr );
    }

    SECTION("Passing nullptr for module, results in nullptr")
    {
        SetLastError(NO_ERROR);

        auto func = DetourFindFunction(nullptr, "FunctionThatDoesntExist");

        REQUIRE( GetLastError() == ERROR_INVALID_PARAMETER );
        REQUIRE( func == nullptr );
    }

    SECTION("Finding ntdll export is successful")
    {
        SetLastError(NO_ERROR);

        auto func = DetourFindFunction("ntdll.dll", "NtDeviceIoControlFile");

        REQUIRE( GetLastError() == NO_ERROR );
        REQUIRE( func != nullptr );
    }
}

TEST_CASE("DetourGetContainingModule", "[module]")
{
    SECTION("Passing nullptr, results in nullptr")
    {
        SetLastError(NO_ERROR);

        auto mod = DetourGetContainingModule(nullptr);

        REQUIRE( GetLastError() == ERROR_BAD_EXE_FORMAT );
        REQUIRE( mod == nullptr );
    }

    SECTION("Passing GetCommandLineW, results in kernel32 HMODULE")
    {
        SetLastError(ERROR_INVALID_HANDLE);

        auto mod = DetourGetContainingModule(GetCommandLineW);

        REQUIRE( GetLastError() == NO_ERROR );
        REQUIRE( mod == LoadLibraryW(L"kernel32.dll") );
    }

    SECTION("Passing own function, results in own HMODULE")
    {
        SetLastError(ERROR_INVALID_HANDLE);

        auto mod = DetourGetContainingModule(NoopFunction);

        REQUIRE( GetLastError() == NO_ERROR );
        REQUIRE( mod == reinterpret_cast<HMODULE>(&__ImageBase) );
    }
}

TEST_CASE("DetourGetEntyPoint", "[module]")
{
    SECTION("Passing nullptr, results in CRT entrypoint")
    {
        SetLastError(ERROR_INVALID_HANDLE);

        auto entry = DetourGetEntryPoint(nullptr);

        REQUIRE( GetLastError() == NO_ERROR );
        REQUIRE( EquivalentFunctions( entry, mainCRTStartup ) );
    }

    SECTION("Passing nullptr, equals executing image")
    {
        REQUIRE( DetourGetEntryPoint(nullptr) ==
                 DetourGetEntryPoint(reinterpret_cast<HMODULE>(&__ImageBase)) );
    }

    SECTION("Passing ImageBase, results in CRT main")
    {
        SetLastError(ERROR_INVALID_HANDLE);

        auto entry = DetourGetEntryPoint(reinterpret_cast<HMODULE>(&__ImageBase));

        REQUIRE( GetLastError() == NO_ERROR );
        REQUIRE( EquivalentFunctions( entry, mainCRTStartup ) );
    }

    SECTION("Corrupt image DOS header magic, results in bad exe format error")
    {
        ImageCorruptor corruptor(&__ImageBase);
        corruptor.ModifyDosMagic(0xDEAD);

        SetLastError(NO_ERROR);

        auto entry = DetourGetEntryPoint(reinterpret_cast<HMODULE>(&__ImageBase));

        REQUIRE( GetLastError() == ERROR_BAD_EXE_FORMAT );
        REQUIRE( entry == nullptr );
    }

    SECTION("Corrupt image NT header signature, results in invalid signature error")
    {
        ImageCorruptor corruptor(&__ImageBase);
        corruptor.ModifyNtSignature(0xDEADBEEF);

        SetLastError(NO_ERROR);

        auto entry = DetourGetEntryPoint(reinterpret_cast<HMODULE>(&__ImageBase));

        REQUIRE( GetLastError() == ERROR_INVALID_EXE_SIGNATURE );
        REQUIRE( entry == nullptr );
    }
}

TEST_CASE("DetourGetModuleSize", "[module]")
{
    SECTION("Passing nullptr, results in current module size")
    {
        SetLastError(ERROR_INVALID_HANDLE);

        auto size = DetourGetModuleSize(nullptr);

        REQUIRE( GetLastError() == NO_ERROR );
        REQUIRE( size > 0 );
    }

    SECTION("Passing stack, results in error")
    {
        SetLastError(NO_ERROR);

        int value;
        auto size = DetourGetModuleSize(reinterpret_cast<HMODULE>(&value));

        REQUIRE( GetLastError() == ERROR_BAD_EXE_FORMAT);
        REQUIRE( size == 0 );
    }

    SECTION("Passing nullptr, equals executing image")
    {
        REQUIRE( DetourGetModuleSize(nullptr) ==
                 DetourGetModuleSize(reinterpret_cast<HMODULE>(&__ImageBase)) );
    }

    SECTION("Corrupt image DOS header magic, results in bad exe format error")
    {
        ImageCorruptor corruptor(&__ImageBase);
        corruptor.ModifyDosMagic(0xDEAD);

        SetLastError(NO_ERROR);

        auto size = DetourGetModuleSize(reinterpret_cast<HMODULE>(&__ImageBase));

        REQUIRE( GetLastError() == ERROR_BAD_EXE_FORMAT );
        REQUIRE( size == 0 );
    }

    SECTION("Corrupt image NT header signature, results in invalid signature error")
    {
        ImageCorruptor corruptor(&__ImageBase);
        corruptor.ModifyNtSignature(0xDEADBEEF);

        SetLastError(NO_ERROR);

        auto size = DetourGetModuleSize(reinterpret_cast<HMODULE>(&__ImageBase));
        REQUIRE( GetLastError() == ERROR_INVALID_EXE_SIGNATURE );
        REQUIRE( size == 0 );
    }
}

TEST_CASE("DetourEnumerateModules", "[module]")
{
    SECTION("Passing nullptr, results in current module being returned")
    {
        SetLastError(ERROR_INVALID_HANDLE);

        auto mod = DetourEnumerateModules(nullptr);

        REQUIRE( GetLastError() == NO_ERROR );
        REQUIRE( mod != NULL );
    }

    SECTION("Passing stack, results in module")
    {
        SetLastError(NO_ERROR);

        int value;
        auto mod = DetourEnumerateModules(reinterpret_cast<HMODULE>(&value));

        REQUIRE( GetLastError() == NO_ERROR );
        REQUIRE( mod != NULL );
    }
}

// Export test function, only used for test assertions.
//
__declspec(dllexport) void TestFunctionExport() { }

// Context object passed to DetourEnumerateExport(..)
//
struct EnumerateExportsTestContext
{
    // Number of exports 
    //
    int ExportCount { 0 };

    // If the 'TestFunctionExport' export exists in the module.
    //
    bool ExportFound { false };
};

// Callback for each modue enumerated with DetourEnumerateExport(..)
//
BOOL CALLBACK ExportCallback(
    _In_opt_ PVOID pContext,
    _In_ ULONG nOrdinal,
    _In_opt_ LPCSTR pszSymbol,
    _In_opt_ PVOID pbTarget)
{
    (void)pContext;
    (void)pbTarget;
    (void)nOrdinal;

    EnumerateExportsTestContext* context =
        reinterpret_cast<EnumerateExportsTestContext*>(pContext);

    context->ExportCount++;

    context->ExportFound |= Catch::contains(pszSymbol, "TestFunctionExport");

    return TRUE;
}

TEST_CASE("DetourEnumerateExports", "[module]")
{
    SECTION("Passing nullptr all, results in failure.")
    {
        SetLastError(NO_ERROR);

        auto success = DetourEnumerateExports(nullptr, nullptr, nullptr);

        REQUIRE( GetLastError() == ERROR_INVALID_PARAMETER );
        REQUIRE_FALSE( success );
    }

    SECTION("Passing nullptr for just the module, resolves export in current modulee.")
    {
        SetLastError(ERROR_INVALID_HANDLE);

        EnumerateExportsTestContext context {};
        auto success = DetourEnumerateExports(nullptr, &context, ExportCallback);

        REQUIRE( GetLastError() == NO_ERROR );
        REQUIRE( success );
        REQUIRE( context.ExportCount == 1 );
        REQUIRE( context.ExportFound );
    }

    SECTION("Passing current module, resolves export correctly.")
    {
        SetLastError(ERROR_INVALID_HANDLE);

        EnumerateExportsTestContext context {};
        auto mod = reinterpret_cast<HMODULE>(&__ImageBase);
        auto success = DetourEnumerateExports(mod, &context, ExportCallback);

        REQUIRE( GetLastError() == NO_ERROR );
        REQUIRE( success );

        REQUIRE( context.ExportCount == 1 );
        REQUIRE( context.ExportFound );
    }

    SECTION("Passing stack, results in error")
    {
        SetLastError(NO_ERROR);

        int value;
        auto mod = reinterpret_cast<HMODULE>(&value);

        EnumerateExportsTestContext context {};
        auto success = DetourEnumerateExports(mod, &context, ExportCallback);

        REQUIRE( GetLastError() == ERROR_BAD_EXE_FORMAT);
        REQUIRE_FALSE( success );
    }

    SECTION("Corrupt image DOS header magic, results in bad exe format error")
    {
        ImageCorruptor corruptor(&__ImageBase);
        corruptor.ModifyDosMagic(0xDEAD);

        SetLastError(NO_ERROR);

        EnumerateExportsTestContext context {};
        auto mod = reinterpret_cast<HMODULE>(&__ImageBase);
        auto success = DetourEnumerateExports(mod, &context, ExportCallback);

        REQUIRE( GetLastError() == ERROR_BAD_EXE_FORMAT );
        REQUIRE_FALSE( success );
    }

    SECTION("Corrupt image NT header signature, results in invalid signature error")
    {
        ImageCorruptor corruptor(&__ImageBase);
        corruptor.ModifyNtSignature(0xDEADBEEF);

        SetLastError(NO_ERROR);

        EnumerateExportsTestContext context {};
        auto mod = reinterpret_cast<HMODULE>(&__ImageBase);
        auto success = DetourEnumerateExports(mod, &context, ExportCallback);

        REQUIRE( GetLastError() == ERROR_INVALID_EXE_SIGNATURE );
        REQUIRE_FALSE( success );
    }
}

// Context object passed to DetourEnumerateimportsExport(..)
//
struct EnumerateImportsTestContext
{
    // Number of imports
    //
    int ImportCount { 0 };

    // If the 'TestFunctionExport' export exists in the module.
    //
    bool ImportModuleFound { false };

    // Number of imports
    //
    int ImportFuncCount { 0 };

    // If the 'TestFunctionExport' export exists in the module.
    //
    bool ImportFuncFound { false };
};

// Callback for each module enumerated with DetourEnumerateImports(..)
//
BOOL WINAPI ImportFileCallback(PVOID pContext, HMODULE, PCSTR pszFile)
{
    EnumerateImportsTestContext* context =
        reinterpret_cast<EnumerateImportsTestContext*>(pContext);

    context->ImportCount++;
    context->ImportModuleFound |= Catch::contains(pszFile, "ntdll");

    return TRUE;
}

// Callback for each function enumerated with DetourEnumerateImports(..)
//
BOOL WINAPI ImportFuncCallback(_In_opt_ PVOID pContext,
                               _In_ DWORD nOrdinal,
                               _In_opt_ LPCSTR pszFunc,
                               _In_opt_ PVOID pvFunc)
{
    UNREFERENCED_PARAMETER(nOrdinal);
    UNREFERENCED_PARAMETER(pszFunc);
    UNREFERENCED_PARAMETER(pvFunc);

    EnumerateImportsTestContext* context =
        reinterpret_cast<EnumerateImportsTestContext*>(pContext);

    context->ImportFuncCount++;
 
    return TRUE;
}

TEST_CASE("DetourEnumerateImports", "[module]")
{
    SECTION("Passing nullptr all, results in invalid parameter.")
    {
        SetLastError(NO_ERROR);

        auto success = DetourEnumerateImports(nullptr, nullptr, nullptr, nullptr);

        REQUIRE( GetLastError() == ERROR_INVALID_PARAMETER );
        REQUIRE_FALSE( success );
    }

    SECTION("Passing nullptr for module callback, results in invalid parameter.")
    {
        SetLastError(NO_ERROR);

        EnumerateImportsTestContext context {};
        auto success = DetourEnumerateImports(nullptr, &context, ImportFileCallback, nullptr);

        REQUIRE( GetLastError() == ERROR_INVALID_PARAMETER );
        REQUIRE_FALSE( success );
        REQUIRE( context.ImportCount == 0 );
        REQUIRE_FALSE( context.ImportModuleFound );
    }

    SECTION("Passing nullptr for function callback, resolves in invalid parameter.")
    {
        SetLastError(ERROR_INVALID_HANDLE);

        EnumerateImportsTestContext context {};
        auto success = DetourEnumerateImports(nullptr, &context, nullptr, ImportFuncCallback);

        REQUIRE( GetLastError() == ERROR_INVALID_PARAMETER );
        REQUIRE_FALSE( success );

        REQUIRE( context.ImportFuncCount == 0 );
        REQUIRE_FALSE( context.ImportFuncFound );
    }
}

TEST_CASE("DetourGetSizeOfPayloads", "[module]")
{
    SECTION("Passing nullptr for module, is successful.")
    {
        SetLastError(ERROR_INVALID_HANDLE);

        auto size = DetourGetSizeOfPayloads(nullptr);

        REQUIRE( GetLastError() == NO_ERROR );
        REQUIRE( size == sizeof(CPrivateStuff) );
    }

    SECTION("Passing nullptr is the same as current module.")
    {
        SetLastError(ERROR_INVALID_HANDLE);

        auto mod = reinterpret_cast<HMODULE>(&__ImageBase);

        auto nullSize = DetourGetSizeOfPayloads(nullptr);
        auto modSize = DetourGetSizeOfPayloads(mod);

        REQUIRE( modSize == nullSize );
    }

    SECTION("Passing a module with no payload, results in exe marked invalid.")
    {
        auto mod = GetModuleHandleW(L"ntdll.dll");

        SetLastError(NO_ERROR);

        auto size = DetourGetSizeOfPayloads(mod);

        REQUIRE( GetLastError() == ERROR_EXE_MARKED_INVALID );
        REQUIRE( size == 0 );
    }

    SECTION("Passing stack, results in error")
    {
        SetLastError(NO_ERROR);

        int value;
        auto mod = reinterpret_cast<HMODULE>(&value);

        auto size = DetourGetSizeOfPayloads(mod);

        REQUIRE( GetLastError() == ERROR_BAD_EXE_FORMAT );
        REQUIRE( size == 0 );
    }

    SECTION("Corrupt image DOS header magic, results in bad exe format error")
    {
        ImageCorruptor corruptor(&__ImageBase);
        corruptor.ModifyDosMagic(0xDEAD);

        SetLastError(NO_ERROR);

        auto mod = reinterpret_cast<HMODULE>(&__ImageBase);
        auto size = DetourGetSizeOfPayloads(mod);

        REQUIRE( GetLastError() == ERROR_BAD_EXE_FORMAT );
        REQUIRE( size == 0 );
    }

    SECTION("Corrupt image NT header signature, results in invalid signature error")
    {
        ImageCorruptor corruptor(&__ImageBase);
        corruptor.ModifyNtSignature(0xDEADBEEF);

        SetLastError(NO_ERROR);

        auto mod = reinterpret_cast<HMODULE>(&__ImageBase);
        auto size = DetourGetSizeOfPayloads(mod);

        REQUIRE( GetLastError() == ERROR_INVALID_EXE_SIGNATURE );
        REQUIRE( size == 0 );
    }
}

TEST_CASE("DetourFindPayload", "[module]")
{
    SECTION("Passing empty guid, fails.")
    {
        SetLastError(NO_ERROR);

        HMODULE module {};
        GUID guid {};
        DWORD data {};

        auto payload = DetourFindPayload(module, guid, &data);

        REQUIRE( payload == nullptr );
        REQUIRE( data == 0 );
        REQUIRE( GetLastError() == ERROR_INVALID_HANDLE );
    }

    SECTION("Passing nullptr for module with correct GUID, is successful.")
    {
        SetLastError(ERROR_INVALID_HANDLE);

        HMODULE module {};
        DWORD data {};

        auto payload = DetourFindPayload(module, TEST_PAYLOAD_GUID, &data);

        REQUIRE( GetLastError() == NO_ERROR );
        REQUIRE( payload != nullptr );
        REQUIRE( data == TEST_PAYLOAD_SIZE );

        char* szPayloadMessage = reinterpret_cast<char*>(payload);
        REQUIRE_THAT( szPayloadMessage, Catch::Matchers::Contains("123") );
    }
}

TEST_CASE("DetourFindPayloadEx", "[module]")
{
    SECTION("Passing empty guid, fails.")
    {
        SetLastError(NO_ERROR);

        GUID guid {};
        DWORD data {};
        auto payload = DetourFindPayloadEx(guid, &data);

        REQUIRE( payload == nullptr );
        REQUIRE( data == 0 );

        // This returns different values on different versions of windows.
        //
        REQUIRE( (GetLastError() == ERROR_MOD_NOT_FOUND || GetLastError() == ERROR_INVALID_HANDLE) );
    }

    SECTION("Finding module with correct GUID, is successful.")
    {
        SetLastError(ERROR_INVALID_HANDLE);

        DWORD data {};
        auto payload = DetourFindPayloadEx(TEST_PAYLOAD_GUID, &data);

        REQUIRE( GetLastError() == NO_ERROR );
        REQUIRE( payload != nullptr );
        REQUIRE( data == TEST_PAYLOAD_SIZE );

        char* szPayloadMessage = reinterpret_cast<char*>(payload);
        REQUIRE_THAT( szPayloadMessage, Catch::Matchers::Contains("123") );
    }
}

TEST_CASE("DetourCopyPayloadToProcessEx", "[module]")
{
    // {44FA1CE0-1DA5-4AFC-946E-F96890C38673}
    static constexpr GUID guid = { 0x44fa1ce0, 0x1da5, 0x4afc, { 0x94, 0x6e, 0xf9, 0x68, 0x90, 0xc3, 0x86, 0x73 } };
    static constexpr std::uint32_t data = 0xDEADBEEF;

    SECTION("Passing NULL process handle, results in error")
    {
        const auto ptr = DetourCopyPayloadToProcessEx(NULL, guid, &data, sizeof(data));
        REQUIRE(GetLastError() == ERROR_INVALID_HANDLE);
        REQUIRE(ptr == nullptr);
    }

    SECTION("Writing to own process, results in valid pointer")
    {
        const auto ptr = reinterpret_cast<std::uint32_t*>(DetourCopyPayloadToProcessEx(GetCurrentProcess(), guid, &data, sizeof(data)));
        REQUIRE(GetLastError() == NO_ERROR);
        REQUIRE(*ptr == data);
    }

    SECTION("Writing to different process, can be read with ReadProcessMemory")
    {
        // create a suspended copy of ourself to do things with.
        TerminateOnScopeExit process{};
        REQUIRE(SUCCEEDED(CreateSuspendedCopy(process)));

        const auto ptr = DetourCopyPayloadToProcessEx(process.information.hProcess, guid, &data, sizeof(data));
        REQUIRE(GetLastError() == NO_ERROR);
        REQUIRE(ptr != nullptr);

        std::uint32_t retrieved_data{};
        REQUIRE(ReadProcessMemory(process.information.hProcess, ptr, &retrieved_data, sizeof(retrieved_data), nullptr));
        REQUIRE(retrieved_data == data);
    }
}

TEST_CASE("DetourFindRemotePayload", "[module]")
{
    SECTION("Passing NULL process handle, results in error")
    {
        const auto ptr = DetourFindRemotePayload(NULL, TEST_PAYLOAD_GUID, nullptr);
        REQUIRE(GetLastError() == ERROR_INVALID_HANDLE);
        REQUIRE(ptr == nullptr);
    }

    SECTION("Finding null GUID from own process, results in error")
    {
        const GUID guid{};

        const auto ptr = DetourFindRemotePayload(GetCurrentProcess(), guid, nullptr);
        REQUIRE(GetLastError() == ERROR_MOD_NOT_FOUND);
        REQUIRE(ptr == nullptr);
    }

    SECTION("Finding null GUID from different process, results in error")
    {
        // create a suspended copy of ourself to do things with.
        TerminateOnScopeExit process{};
        REQUIRE(SUCCEEDED(CreateSuspendedCopy(process)));

        const GUID guid{};
        const auto ptr = DetourFindRemotePayload(process.information.hProcess, guid, nullptr);
        REQUIRE(GetLastError() == ERROR_MOD_NOT_FOUND);
        REQUIRE(ptr == nullptr);
    }

    SECTION("Finding valid GUID from own process, results in valid pointer")
    {
        DWORD size = 0;
        const auto ptr = reinterpret_cast<std::uint32_t*>(DetourFindRemotePayload(GetCurrentProcess(), TEST_PAYLOAD_GUID, &size));
        REQUIRE(GetLastError() == NO_ERROR);
        REQUIRE(ptr != nullptr);
        REQUIRE(size == TEST_PAYLOAD_SIZE);

        char* szPayloadMessage = reinterpret_cast<char*>(ptr);
        REQUIRE_THAT(szPayloadMessage, Catch::Matchers::Contains("123"));
    }

    SECTION("Finding valid GUID from different process, can be read with ReadProcessMemory")
    {
        // create a suspended copy of ourself to do things with.
        TerminateOnScopeExit process{};
        REQUIRE(SUCCEEDED(CreateSuspendedCopy(process)));

        DWORD size = 0;
        const auto ptr = DetourFindRemotePayload(process.information.hProcess, TEST_PAYLOAD_GUID, &size);
        REQUIRE(GetLastError() == NO_ERROR);
        REQUIRE(ptr != nullptr);
        REQUIRE(size == TEST_PAYLOAD_SIZE);

        SIZE_T bytesRead = 0;
        char szPayloadMessage[TEST_PAYLOAD_SIZE];
        REQUIRE(ReadProcessMemory(process.information.hProcess, ptr, &szPayloadMessage, TEST_PAYLOAD_SIZE, &bytesRead));
        REQUIRE(bytesRead == TEST_PAYLOAD_SIZE);
        REQUIRE_THAT(szPayloadMessage, Catch::Matchers::Contains("123"));
    }
}

TEST_CASE("DetourRestoreAfterWith", "[module]")
{
    // TODO: Needs to be written.
}

TEST_CASE("DetourRestoreAfterWithEx", "[module]")
{
    // TODO: Needs to be written.
}

// Define the import symbol so that we can get the address of the IAT entry for a static import
#pragma warning(push)
#pragma warning(disable:4483) // disable warning/error about __identifier(<string>)
#if defined(_X86_)
#define __imp_SetLastError      __identifier("_imp__SetLastError@4")
#elif defined(_ARM64EC_)
// In Arm64EC binaries, __imp_aux_foo points the primary IAT entry
// for foo, and __imp_foo points to the auxiliary IAT entry for foo.
#define __imp_SetLastError      __identifier("__imp_aux_SetLastError")
#endif

extern "C" extern void *__imp_SetLastError;

TEST_CASE("DetourIsFunctionImported", "[module]")
{
    SECTION("Passing NULL code pointer, results in false")
    {
        REQUIRE(!DetourIsFunctionImported(NULL, reinterpret_cast<PBYTE>(&__imp_SetLastError)));
    }
    
    SECTION("Passing NULL target, results in false")
    {
        REQUIRE(!DetourIsFunctionImported(reinterpret_cast<PBYTE>(&__ImageBase), NULL));
    }
    
    SECTION("Passing imported function, results in true")
    {
        REQUIRE(DetourIsFunctionImported(reinterpret_cast<PBYTE>(&__ImageBase), reinterpret_cast<PBYTE>(&__imp_SetLastError)));
    }
}

#pragma warning(pop)
