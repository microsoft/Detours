//////////////////////////////////////////////////////////////////////////////
//
//  Unit Tests for Detours Create With API (test_create_with.cpp of unittests.exe)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#include "catch.hpp"
#include "windows.h"
#include "detours.h"
#include "rpc.h"
#include "process_helpers.h"

// sample data
const std::uint32_t data = 0xDEADBEEF;

// use an unique GUID each time because tests might use each other's payloads otherwise
static GUID GenerateGuid()
{
    GUID guid{};
    REQUIRE(UuidCreate(&guid) == RPC_S_OK);
    return guid;
}

TEST_CASE("DetourCopyPayloadToProcessEx", "[create with]")
{
    const GUID guid = GenerateGuid();

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

TEST_CASE("DetourFindRemotePayload", "[create with]")
{
    const GUID guid = GenerateGuid();

    SECTION("Passing NULL process handle, results in error")
    {
        const auto ptr = DetourFindRemotePayload(NULL, guid, nullptr);
        REQUIRE(GetLastError() == ERROR_INVALID_HANDLE);
        REQUIRE(ptr == nullptr);
    }

    SECTION("Finding random GUID from own process, results in error")
    {
        const auto ptr = DetourFindRemotePayload(GetCurrentProcess(), guid, nullptr);
        REQUIRE(GetLastError() == ERROR_MOD_NOT_FOUND);
        REQUIRE(ptr == nullptr);
    }

    SECTION("Finding random GUID from different process, results in error")
    {
        // create a suspended copy of ourself to do things with.
        TerminateOnScopeExit process{};
        REQUIRE(SUCCEEDED(CreateSuspendedCopy(process)));

        const auto ptr = DetourFindRemotePayload(process.information.hProcess, guid, nullptr);
        REQUIRE(GetLastError() == ERROR_MOD_NOT_FOUND);
        REQUIRE(ptr == nullptr);
    }

    SECTION("Finding valid GUID from own process, results in valid pointer")
    {
        DetourCopyPayloadToProcessEx(GetCurrentProcess(), guid, &data, sizeof(data));
        REQUIRE(GetLastError() == NO_ERROR);

        const auto ptr = reinterpret_cast<std::uint32_t*>(DetourFindRemotePayload(GetCurrentProcess(), guid, nullptr));
        REQUIRE(GetLastError() == NO_ERROR);
        REQUIRE(*ptr == data);
    }

    SECTION("Finding valid GUID from different process, can be read with ReadProcessMemory")
    {
        // create a suspended copy of ourself to do things with.
        TerminateOnScopeExit process{};
        REQUIRE(SUCCEEDED(CreateSuspendedCopy(process)));

        DetourCopyPayloadToProcessEx(process.information.hProcess, guid, &data, sizeof(data));
        REQUIRE(GetLastError() == NO_ERROR);

        const auto ptr = DetourFindRemotePayload(process.information.hProcess, guid, nullptr);
        REQUIRE(GetLastError() == NO_ERROR);
        REQUIRE(ptr != nullptr);

        std::uint32_t retrieved_data{};
        REQUIRE(ReadProcessMemory(process.information.hProcess, ptr, &retrieved_data, sizeof(retrieved_data), nullptr));
        REQUIRE(retrieved_data == data);
    }
}

TEST_CASE("DetourFindPayloadEx", "[create with]")
{
    const GUID guid = GenerateGuid();

    SECTION("Finding random GUID, results in error")
    {
        const auto ptr = DetourFindPayloadEx(guid, nullptr);
        REQUIRE(GetLastError() == ERROR_MOD_NOT_FOUND);
        REQUIRE(ptr == nullptr);
    }

    SECTION("Finding valid GUID, results in valid pointer")
    {
        DetourCopyPayloadToProcessEx(GetCurrentProcess(), guid, &data, sizeof(data));
        REQUIRE(GetLastError() == NO_ERROR);

        const auto ptr = reinterpret_cast<std::uint32_t*>(DetourFindPayloadEx(guid, nullptr));
        REQUIRE(GetLastError() == NO_ERROR);
        REQUIRE(*ptr == data);
    }
}
