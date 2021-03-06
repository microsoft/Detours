//////////////////////////////////////////////////////////////////////////////
//
//  Test Payload for Detours Module API tests (payload.h of unittests.exe)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#pragma once
#include <cstddef>
#include "windows.h"
#include "detours.h"

// {85ECA590-6E6A-40FC-BA75-451D96A2A746}
static constexpr GUID TEST_PAYLOAD_GUID = 
{ 0x85eca590, 0x6e6a, 0x40fc, { 0xba, 0x75, 0x45, 0x1d, 0x96, 0xa2, 0xa7, 0x46 } };

static constexpr std::size_t TEST_PAYLOAD_SIZE = 32;

struct CPrivateStuff
{
    DETOUR_SECTION_HEADER   header;
    DETOUR_SECTION_RECORD   record;
    CHAR                    szMessage[TEST_PAYLOAD_SIZE];
};
