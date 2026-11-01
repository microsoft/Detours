//////////////////////////////////////////////////////////////////////////////
//
//  Unit Tests for Detours Disassembly API (test_disasm_api.cpp of unittests.exe)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#include "catch.hpp"
#include "windows.h"

#define DETOURS_INTERNAL

#include "detours.h"

#include <string.h>

#if defined(DETOURS_X86) || defined(DETOURS_X64)

// Copy an instruction into a padded source buffer and verify the length
// the disassembler reports and the bytes it produces.
//
static void
CheckInstructionCopy(
    _In_reads_bytes_(cbCode) const BYTE *pbCode,
    _In_ DWORD cbCode,
    _In_ DWORD cbExpected
    )
{
    BYTE pbSrc[32];
    BYTE pbDst[32];
    PVOID pTarget = NULL;
    LONG lExtra = 0;

    memset(pbSrc, 0x90, sizeof(pbSrc));
    memset(pbDst, 0xCC, sizeof(pbDst));
    memcpy(pbSrc, pbCode, cbCode);

    PVOID pNext = DetourCopyInstruction(pbDst, NULL, pbSrc, &pTarget, &lExtra);

    REQUIRE( pNext == pbSrc + cbExpected );
    REQUIRE( memcmp(pbDst, pbCode, cbExpected) == 0 );
    REQUIRE( lExtra == 0 );
}

TEST_CASE("DetourCopyInstruction", "[disasm]")
{
    SECTION("VCVTUDQ2PH (EVEX MAP5 F2 7A)")
    {
        static const BYTE rbCode[] = { 0x62, 0xF5, 0x7F, 0x48, 0x7A, 0xC0 };
        CheckInstructionCopy(rbCode, (DWORD)sizeof(rbCode), 6);
    }

    SECTION("VCVTPH2QQ (EVEX MAP5 66 7B)")
    {
        static const BYTE rbCode[] = { 0x62, 0xF5, 0x7D, 0x48, 0x7B, 0xC0 };
        CheckInstructionCopy(rbCode, (DWORD)sizeof(rbCode), 6);
    }

    SECTION("VCVTTPH2UQQ (EVEX MAP5 66 78)")
    {
        static const BYTE rbCode[] = { 0x62, 0xF5, 0x7D, 0x48, 0x78, 0xC1 };
        CheckInstructionCopy(rbCode, (DWORD)sizeof(rbCode), 6);
    }

    SECTION("VADDPH (EVEX MAP5 58)")
    {
        static const BYTE rbCode[] = { 0x62, 0xF5, 0x7C, 0x48, 0x58, 0xC1 };
        CheckInstructionCopy(rbCode, (DWORD)sizeof(rbCode), 6);
    }

    SECTION("VCVTUDQ2PH with disp32 (EVEX MAP5 F2 7A)")
    {
        static const BYTE rbCode[] = { 0x62, 0xF5, 0x7F, 0x48, 0x7A, 0x80,
                                       0x01, 0x02, 0x03, 0x04 };
        CheckInstructionCopy(rbCode, (DWORD)sizeof(rbCode), 10);
    }

    SECTION("VCMPPH (EVEX MAP3 C2 ib)")
    {
        static const BYTE rbCode[] = { 0x62, 0xF3, 0x7C, 0x48, 0xC2, 0xC1, 0x05 };
        CheckInstructionCopy(rbCode, (DWORD)sizeof(rbCode), 7);
    }
}

#endif // DETOURS_X86 || DETOURS_X64
