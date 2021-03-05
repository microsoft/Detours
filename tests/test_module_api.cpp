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

// Expose the image base of the current module for test assertions.
//
extern "C" IMAGE_DOS_HEADER __ImageBase;

// Expose default module entry point for test assertions.
//
extern "C" int mainCRTStartup();

// Dummy function pointer used for tests.
//
void NoopFunction() { }

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
        REQUIRE( mod == LoadLibrary("kernel32.dll") );
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
        REQUIRE( entry == mainCRTStartup );
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
        REQUIRE( entry == mainCRTStartup );
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
        REQUIRE( mod == reinterpret_cast<HMODULE>(&__ImageBase) );
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

struct CPrivateStuff
{
    DETOUR_SECTION_HEADER   header;
    DETOUR_SECTION_RECORD   record;
    CHAR                    szMessage[32];
};

GUID PayloadGUID
{ /* d9ab8a40-f4cc-11d1-b6d7-006097b010e3 */
    0xd9ab8a40,
    0xf4cc,
    0x11d1,
    {0xb6, 0xd7, 0x00, 0x60, 0x97, 0xb0, 0x10, 0xe3}
};

// Define a detours payload for testing.
//
#pragma data_seg(".detour")

static CPrivateStuff private_stuff = {
    DETOUR_SECTION_HEADER_DECLARE(sizeof(CPrivateStuff)),
    {
        (sizeof(CPrivateStuff) - sizeof(DETOUR_SECTION_HEADER)),
        0,
        { /* d9ab8a40-f4cc-11d1-b6d7-006097b010e3 */
            0xd9ab8a40,
            0xf4cc,
            0x11d1,
            {0xb6, 0xd7, 0x00, 0x60, 0x97, 0xb0, 0x10, 0xe3}
        }
    },
    "Testing Payload 123"
};

#pragma data_seg()

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

        auto payload = DetourFindPayload(module, PayloadGUID, &data);

        REQUIRE( GetLastError() == NO_ERROR );
        REQUIRE( payload != nullptr );
        REQUIRE( data == sizeof(CPrivateStuff::szMessage) );

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
        auto payload = DetourFindPayloadEx(PayloadGUID, &data);

        REQUIRE( GetLastError() == NO_ERROR );
        REQUIRE( payload != nullptr );
        REQUIRE( data == sizeof(CPrivateStuff::szMessage) );

        char* szPayloadMessage = reinterpret_cast<char*>(payload);
        REQUIRE_THAT( szPayloadMessage, Catch::Matchers::Contains("123") );
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


