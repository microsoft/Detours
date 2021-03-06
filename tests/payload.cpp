//////////////////////////////////////////////////////////////////////////////
//
//  Test Payload for Detours Module API tests (payload.cpp of unittests.exe)
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#include "payload.h"

// Define a detours payload for testing.
//
#pragma data_seg(".detour")

static CPrivateStuff private_stuff = {
    DETOUR_SECTION_HEADER_DECLARE(sizeof(CPrivateStuff)),
    {
        (sizeof(CPrivateStuff) - sizeof(DETOUR_SECTION_HEADER)),
        0,
        TEST_PAYLOAD_GUID
    },
    "Testing Payload 123"
};

#pragma data_seg()
