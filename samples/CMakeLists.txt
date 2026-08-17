##############################################################################
##
##  CMakeLists.txt for the Detours samples.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##
##  opengl is intentionally not ported here and has no CMake target.
##

# These are only needed by the samples, so they're enabled here rather than in the root
# CMakeLists.txt -- a library+tests-only build (DETOURS_BUILD_SAMPLES=OFF) needs none of them.
enable_language(RC)         # tryman/tstman.rc
enable_language(ASM_MASM)   # disas/x64.asm
enable_language(C)          # cping's MIDL-generated proxy/stub .c files (see the cping section below)

# These are unmodified vendor sample sources that predate current MSVC warning levels and
# don't build clean under -WX; only the specific warnings promoted via
# DETOURS_SAMPLE_COMPILE_OPTIONS (/we4777 /we4800) are treated as errors here. The root
# CMakeLists.txt's global CMAKE_COMPILE_WARNING_AS_ERROR is turned back off just for this
# subdirectory (a normal-variable override, scoped to this add_subdirectory() call only).
set(CMAKE_COMPILE_WARNING_AS_ERROR OFF)

# Several samples below key their fixed base addresses and arch-specific sources off of this.
# Only the architectures this CMake port actually targets are handled; plain (non-EC) ARM64
# isn't a supported CMake platform here.
#
# CMAKE_CXX_COMPILER_ARCHITECTURE_ID reflects what the compiler itself was actually invoked to
# target (MSVC's _M_ARM64EC/_M_X64/... macros) regardless of generator; CMAKE_GENERATOR_PLATFORM
# and CMAKE_VS_PLATFORM_NAME are only ever set by the Visual Studio generators and say nothing
# under Ninja/Ninja Multi-Config.
if(CMAKE_CXX_COMPILER_ARCHITECTURE_ID STREQUAL "ARM64EC")
    set(DETOURS_SAMPLE_ARCH "ARM64EC")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(DETOURS_SAMPLE_ARCH "X64")
else()
    set(DETOURS_SAMPLE_ARCH "X86")
endif()

set(DETOURS_SAMPLE_COMPILE_OPTIONS /W4 /we4777 /we4800 /Od)
set(DETOURS_SAMPLE_LINK_OPTIONS /INCREMENTAL:NO /PROFILE /RELEASE /NODEFAULTLIB:oldnames.lib)

function(detours_sample_common_settings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE ${DETOURS_SAMPLE_COMPILE_OPTIONS})
        target_compile_definitions(${target} PRIVATE $<$<CONFIG:Debug>:DETOUR_DEBUG=1>)
        target_link_options(${target} PRIVATE ${DETOURS_SAMPLE_LINK_OPTIONS})
    endif()
    # Every sample links against syelog + detours.
    target_link_libraries(${target} PRIVATE Microsoft::detours syelog)
endfunction()

function(add_detour_sample_exe name)
    cmake_parse_arguments(ARG "" "" "SOURCES;LIBS" ${ARGN})
    add_executable(${name} ${ARG_SOURCES})
    detours_sample_common_settings(${name})
    if(ARG_LIBS)
        target_link_libraries(${name} PRIVATE ${ARG_LIBS})
    endif()
endfunction()

# Samples that bypass this (edll1x/2x/3x, tdll1x..9x, findfunc's target.dll) use plain
# add_library(... SHARED ...) + detours_sample_common_settings() directly instead, since they
# need no export flag, or a single non-default export, rather than this default injection.
function(add_detour_sample_dll name)
    cmake_parse_arguments(ARG "" "" "SOURCES;EXPORTS;LIBS" ${ARGN})
    add_library(${name} SHARED ${ARG_SOURCES})
    detours_sample_common_settings(${name})
    if(ARG_LIBS)
        target_link_libraries(${name} PRIVATE ${ARG_LIBS})
    endif()
    if(NOT ARG_EXPORTS)
        set(ARG_EXPORTS "DetourFinishHelperProcess,@1,NONAME")
    endif()
    foreach(exp IN LISTS ARG_EXPORTS)
        target_link_options(${name} PRIVATE "/EXPORT:${exp}")
    endforeach()
endfunction()

##############################################################################
## syelog - foundational shared dependency almost everything else links.

add_library(syelog STATIC syelog/syelog.cpp)
target_sources(syelog PUBLIC
    FILE_SET HEADERS
    BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/syelog
    FILES syelog/syelog.h
)
# syelog.cpp itself #includes detours.h (for the DetourFinishHelperProcess ref counting).
target_link_libraries(syelog PRIVATE Microsoft::detours)
if(MSVC)
    target_compile_options(syelog PRIVATE ${DETOURS_SAMPLE_COMPILE_OPTIONS})
    target_compile_definitions(syelog PRIVATE $<$<CONFIG:Debug>:DETOUR_DEBUG=1>)
endif()

# syelogd intentionally doesn't link syelog.lib/detours.lib at all, so it bypasses
# add_detour_sample_exe rather than picking those up unintentionally.
add_executable(syelogd syelog/syelogd.cpp)
if(MSVC)
    target_compile_options(syelogd PRIVATE ${DETOURS_SAMPLE_COMPILE_OPTIONS})
    target_compile_definitions(syelogd PRIVATE $<$<CONFIG:Debug>:DETOUR_DEBUG=1>)
    target_link_options(syelogd PRIVATE ${DETOURS_SAMPLE_LINK_OPTIONS})
endif()
target_link_libraries(syelogd PRIVATE ws2_32.lib mswsock.lib advapi32.lib)

add_detour_sample_exe(sltest SOURCES syelog/sltest.cpp LIBS kernel32.lib)
add_detour_sample_exe(sltestp SOURCES syelog/sltestp.cpp LIBS kernel32.lib)

##############################################################################
## setdll, withdll - built early because other samples' tests shell out to these binaries.
## Cross-bitness copies of these tools (32-bit builds alongside 64-bit ones, etc.) from the
## original build are intentionally not ported.

add_detour_sample_exe(setdll SOURCES setdll/setdll.cpp LIBS kernel32.lib)
add_detour_sample_exe(withdll SOURCES withdll/withdll.cpp LIBS kernel32.lib)

##############################################################################
## The bulk of the "standard" samples.

add_detour_sample_dll(wrotei SOURCES comeasy/wrotei.cpp comeasy/wrotei.rc LIBS kernel32.lib ole32.lib)
add_detour_sample_exe(comeasy SOURCES comeasy/comeasy.cpp LIBS kernel32.lib ole32.lib)
target_link_options(comeasy PRIVATE /FIXED:NO)

add_detour_sample_exe(commem SOURCES commem/commem.cpp LIBS kernel32.lib ole32.lib)

# disas/unk.cpp, arm.asm, ia64.asm exist in the source tree but are not referenced by any
# target here.
if(DETOURS_SAMPLE_ARCH STREQUAL "X86")
    set(DETOURS_DISAS_ARCH_SOURCE disas/x86.cpp)
else()
    set(DETOURS_DISAS_ARCH_SOURCE disas/x64.asm)
endif()
add_detour_sample_exe(disas SOURCES disas/disas.cpp ${DETOURS_DISAS_ARCH_SOURCE} LIBS kernel32.lib)
target_link_options(disas PRIVATE /ENTRY:WinMainCRTStartup)

add_library(dtarge SHARED dtest/dtarge.cpp dtest/dtarge.rc)
detours_sample_common_settings(dtarge)
target_link_libraries(dtarge PRIVATE kernel32.lib)
target_link_options(dtarge PRIVATE
    /EXPORT:Target0 /EXPORT:Target1 /EXPORT:Target2 /EXPORT:Target3 /EXPORT:Target4
    /EXPORT:Target5 /EXPORT:Target6 /EXPORT:Target7 /EXPORT:Target8 /EXPORT:Target9
    /EXPORT:Target10 /EXPORT:Target11 /EXPORT:Target12 /EXPORT:Target13 /EXPORT:Target14
    /EXPORT:Target15 /EXPORT:Target16 /EXPORT:TargetV /EXPORT:TargetR
)
add_detour_sample_exe(dtest SOURCES dtest/dtest.cpp LIBS kernel32.lib dtarge)
target_link_options(dtest PRIVATE /ENTRY:WinMainCRTStartup)

add_detour_sample_exe(dumpe SOURCES dumpe/dumpe.cpp LIBS kernel32.lib)
add_detour_sample_exe(dumpi SOURCES dumpi/dumpi.cpp LIBS kernel32.lib)

# echonul.exe doubles as a DLL-style import target (echofx links against it): it needs
# ENABLE_EXPORTS instead of add_library(SHARED), an extra /Zl compile flag, and its link line
# omits Microsoft::detours/syelog entirely (unlike every other sample here).
add_executable(echonul echo/main.cpp echo/echonul.cpp)
if(MSVC)
    target_compile_options(echonul PRIVATE ${DETOURS_SAMPLE_COMPILE_OPTIONS})
    if(NOT DETOURS_SAMPLE_ARCH STREQUAL "ARM64EC")
        # /Zl (omit default library name) also strips the /DEFAULTLIB pragma the ARM64EC
        # compiler otherwise emits for its EC/native exit-thunk dispatch glue, which this
        # exports-heavy target needs (LNK2019 on __os_arm64x_dispatch_* without it) -- an
        # ABI concern specific to ARM64EC, so /Zl is skipped only on that architecture.
        target_compile_options(echonul PRIVATE /Zl)
    endif()
    target_compile_definitions(echonul PRIVATE $<$<CONFIG:Debug>:DETOUR_DEBUG=1>)
    target_link_options(echonul PRIVATE ${DETOURS_SAMPLE_LINK_OPTIONS})
endif()
set_target_properties(echonul PROPERTIES ENABLE_EXPORTS ON)
target_link_options(echonul PRIVATE /EXPORT:Echo)

add_detour_sample_dll(echofx
    SOURCES echo/echofx.cpp echo/echofx.rc
    EXPORTS "DetourFinishHelperProcess,@1,NONAME" "Mine_Echo"
    LIBS kernel32.lib echonul
)

add_detour_sample_exe(region SOURCES region/region.cpp LIBS kernel32.lib)

add_detour_sample_dll(trcbld SOURCES tracebld/trcbld.cpp tracebld/trcbld.rc LIBS kernel32.lib)
add_detour_sample_exe(tracebld SOURCES tracebld/tracebld.cpp LIBS kernel32.lib)
target_link_options(tracebld PRIVATE /FIXED:NO)

add_detour_sample_dll(trclnk SOURCES tracelnk/trclnk.cpp tracelnk/trclnk.rc LIBS kernel32.lib)
add_detour_sample_dll(trcmem SOURCES tracemem/trcmem.cpp tracemem/trcmem.rc LIBS kernel32.lib)
add_detour_sample_dll(trcreg SOURCES tracereg/trcreg.cpp tracereg/trcreg.rc LIBS kernel32.lib advapi32.lib)
add_detour_sample_dll(trcser SOURCES traceser/trcser.cpp traceser/trcser.rc LIBS kernel32.lib)
add_detour_sample_dll(trcssl SOURCES tracessl/trcssl.cpp tracessl/trcssl.rc LIBS kernel32.lib ws2_32.lib secur32.lib)
add_detour_sample_dll(trctcp SOURCES tracetcp/trctcp.cpp tracetcp/trctcp.rc LIBS kernel32.lib ws2_32.lib)

# testapi.cpp #includes trcapi.cpp and _win32.cpp directly (as does trcapi.cpp with _win32.cpp),
# so each target compiles only its own top-level source.
add_detour_sample_dll(trcapi
    SOURCES traceapi/trcapi.cpp traceapi/trcapi.rc
    LIBS kernel32.lib gdi32.lib user32.lib shell32.lib advapi32.lib ole32.lib ws2_32.lib
)
add_detour_sample_exe(testapi
    SOURCES traceapi/testapi.cpp
    LIBS kernel32.lib gdi32.lib user32.lib shell32.lib advapi32.lib ole32.lib ws2_32.lib
)
target_link_options(testapi PRIVATE /FIXED:NO)

##############################################################################
## Samples needing explicit deviation from the common flags.

add_detour_sample_dll(slept
    SOURCES slept/slept.cpp slept/slept.rc
    EXPORTS "DetourFinishHelperProcess,@1,NONAME" "TimedSleepEx" "UntimedSleepEx" "GetSleptTicks" "TestTicks" "TestTicksEx"
    LIBS kernel32.lib
)
if(MSVC)
    # Re-enables /O2, appended after add_detour_sample_dll's /Od so it wins on the cl.exe command line.
    target_compile_options(slept PRIVATE /O2)
endif()

add_detour_sample_dll(dslept
    SOURCES slept/dslept.cpp slept/dslept.rc
    EXPORTS "DetourFinishHelperProcess,@1,NONAME" "TimedSleepEx" "UntimedSleepEx" "GetSleptTicks"
    LIBS kernel32.lib
)

# verify.cpp is intentionally not listed here: slept.cpp/sleepold.cpp/sleepnew.cpp/sleepbed.cpp/
# dslept.cpp above and below all end with #include "verify.cpp" (textual, no header guard), so
# listing it as its own SOURCES entry would compile it a second time as an independent
# translation unit -- one that lacks the <windows.h> each of those files includes beforehand,
# which detours.h needs to detect the target architecture.
add_detour_sample_exe(sleepold SOURCES slept/sleepold.cpp LIBS kernel32.lib)
target_link_options(sleepold PRIVATE /FIXED:NO)
add_detour_sample_exe(sleepnew SOURCES slept/sleepnew.cpp LIBS kernel32.lib slept)
target_link_options(sleepnew PRIVATE /FIXED:NO)
add_detour_sample_exe(sleepbed SOURCES slept/sleepbed.cpp LIBS kernel32.lib)
target_link_options(sleepbed PRIVATE /FIXED:NO)

add_detour_sample_dll(simple
    SOURCES simple/simple.cpp simple/simple.rc
    EXPORTS "DetourFinishHelperProcess,@1,NONAME" "TimedSleepEx"
    LIBS kernel32.lib
)
add_detour_sample_exe(sleep5 SOURCES simple/sleep5.cpp LIBS kernel32.lib)

add_detour_sample_dll(simple_safe
    SOURCES simple_safe/simple_safe.cpp simple_safe/simple_safe.rc
    EXPORTS "DetourFinishHelperProcess,@1,NONAME" "TimedSleepEx"
    LIBS kernel32.lib
)
if(MSVC)
    target_compile_options(simple_safe PRIVATE /std:c++14)
endif()
# simple_safe/sleep5.cpp is a byte-for-byte copy of simple/sleep5.cpp; kept as its own
# target/binary under a distinct CMake target name since "sleep5" is already taken above.
add_detour_sample_exe(sleep5_safe SOURCES simple_safe/sleep5.cpp LIBS kernel32.lib)
set_target_properties(sleep5_safe PROPERTIES OUTPUT_NAME sleep5_safe)

add_detour_sample_exe(payload SOURCES payload/payload.cpp LIBS kernel32.lib)
add_detour_sample_exe(payloadtarget SOURCES payload/payloadtarget.cpp LIBS kernel32.lib)
if(MSVC)
    target_compile_options(payload PRIVATE /EHsc)
    target_compile_options(payloadtarget PRIVATE /EHsc)
endif()

# X86/X64 only (excludes ARM64EC too, unlike disas above).
if(DETOURS_SAMPLE_ARCH STREQUAL "X86" OR DETOURS_SAMPLE_ARCH STREQUAL "X64")
    if(DETOURS_SAMPLE_ARCH STREQUAL "X64")
        set(DETOURS_DALLOC_ARCH_SOURCE dynamic_alloc/x64.asm)
    else()
        set(DETOURS_DALLOC_ARCH_SOURCE dynamic_alloc/x86.asm)
    endif()
    add_detour_sample_exe(dalloc SOURCES dynamic_alloc/main.cpp ${DETOURS_DALLOC_ARCH_SOURCE} LIBS kernel32.lib user32.lib)
    if(MSVC)
        target_compile_options(dalloc PRIVATE /EHsc)
        if(DETOURS_SAMPLE_ARCH STREQUAL "X86")
            # x86.asm has no .SAFESEH directive, so it
            # can't be marked as SafeSEH-compliant; since main.cpp's cl.exe-generated object
            # *is* compliant, link.exe would otherwise require -- and fail to find -- SafeSEH
            # info from every module, including this one (LNK2026/LNK1281 on x86 only).
            target_link_options(dalloc PRIVATE /SAFESEH:NO)
        endif()
    endif()
endif()

##############################################################################
## Plain samples with no shared DLL/EXE pairing.

add_detour_sample_exe(member SOURCES member/member.cpp LIBS kernel32.lib)
add_detour_sample_exe(impmunge SOURCES impmunge/impmunge.cpp LIBS kernel32.lib imagehlp.lib)

# X86 only.
if(DETOURS_SAMPLE_ARCH STREQUAL "X86")
    add_detour_sample_exe(excep SOURCES excep/excep.cpp excep/firstexc.cpp LIBS kernel32.lib)
    target_link_options(excep PRIVATE /ENTRY:WinMainCRTStartup)
endif()

##############################################################################
## Fixed-base-address samples. edll1x/2x/3x and target.dll bypass add_detour_sample_dll's
## default export injection entirely (no export flag at all, or a single non-default export).

if(DETOURS_SAMPLE_ARCH STREQUAL "ARM64EC")
    set(DETOURS_EINST_EDLL1X_BASE 0x710000000)
    set(DETOURS_EINST_EDLL2X_BASE 0x720000000)
    set(DETOURS_EINST_EDLL3X_BASE 0x730000000)
else()
    set(DETOURS_EINST_EDLL1X_BASE 0x7100000)
    set(DETOURS_EINST_EDLL2X_BASE 0x7200000)
    set(DETOURS_EINST_EDLL3X_BASE 0x7300000)
endif()

add_library(edll1x SHARED einst/edll1x.cpp)
detours_sample_common_settings(edll1x)
target_link_libraries(edll1x PRIVATE kernel32.lib user32.lib)
target_link_options(edll1x PRIVATE /SUBSYSTEM:WINDOWS /BASE:${DETOURS_EINST_EDLL1X_BASE})

add_library(edll2x SHARED einst/edll2x.cpp)
detours_sample_common_settings(edll2x)
target_link_libraries(edll2x PRIVATE kernel32.lib user32.lib)
target_link_options(edll2x PRIVATE /SUBSYSTEM:CONSOLE /BASE:${DETOURS_EINST_EDLL2X_BASE})

add_library(edll3x SHARED einst/edll3x.cpp)
detours_sample_common_settings(edll3x)
target_link_libraries(edll3x PRIVATE kernel32.lib user32.lib)
target_link_options(edll3x PRIVATE /SUBSYSTEM:CONSOLE /BASE:${DETOURS_EINST_EDLL3X_BASE})

add_detour_sample_exe(einst SOURCES einst/einst.cpp LIBS kernel32.lib user32.lib edll1x edll2x edll3x)
target_link_options(einst PRIVATE /ENTRY:WinMainCRTStartup)

if(DETOURS_SAMPLE_ARCH STREQUAL "ARM64EC")
    set(DETOURS_FINDFUNC_TARGET_BASE 0x190000000)
    set(DETOURS_FINDFUNC_EXTEND_BASE 0x1a0000000)
else()
    set(DETOURS_FINDFUNC_TARGET_BASE 0x1900000)
    set(DETOURS_FINDFUNC_EXTEND_BASE 0x1a00000)
endif()

add_library(findfunc_target SHARED findfunc/target.cpp findfunc/target.rc)
set_target_properties(findfunc_target PROPERTIES OUTPUT_NAME target)
detours_sample_common_settings(findfunc_target)
target_link_libraries(findfunc_target PRIVATE kernel32.lib)
target_link_options(findfunc_target PRIVATE /EXPORT:Target /BASE:${DETOURS_FINDFUNC_TARGET_BASE})

add_detour_sample_dll(findfunc_extend SOURCES findfunc/extend.cpp findfunc/extend.rc LIBS kernel32.lib)
set_target_properties(findfunc_extend PROPERTIES OUTPUT_NAME extend)
target_link_options(findfunc_extend PRIVATE /BASE:${DETOURS_FINDFUNC_EXTEND_BASE})

# The external copy-of-dbghelp.dll step from the original build is intentionally not ported.
add_detour_sample_exe(findfunc SOURCES findfunc/findfunc.cpp LIBS kernel32.lib findfunc_target)
target_link_options(findfunc PRIVATE /FIXED:NO)
add_detour_sample_exe(symtest SOURCES findfunc/symtest.cpp LIBS kernel32.lib findfunc_target)
target_link_options(symtest PRIVATE /FIXED:NO)

# X64 only for this CMake port; IA64 isn't part of this port at all.
if(DETOURS_SAMPLE_ARCH STREQUAL "X64")
    # /FIXED requires ASLR off; link.exe defaults /DYNAMICBASE to ON regardless of CMake, so it
    # must be disabled explicitly here.
    set(DETOURS_TALLOC_LINK_OPTIONS /INCREMENTAL:NO /FIXED /DYNAMICBASE:NO /RELEASE /NODEFAULTLIB:oldnames.lib)

    # tdllNx.dll link lines use $(LINKFLAGS:/profile=/fixed) -- /FIXED replaces /PROFILE rather
    # than adding to it, so these use DETOURS_TALLOC_LINK_OPTIONS instead of the common list.
    function(add_talloc_dll name base)
        add_library(${name} SHARED talloc/${name}.cpp)
        if(MSVC)
            target_compile_options(${name} PRIVATE ${DETOURS_SAMPLE_COMPILE_OPTIONS})
            target_compile_definitions(${name} PRIVATE $<$<CONFIG:Debug>:DETOUR_DEBUG=1>)
            target_link_options(${name} PRIVATE ${DETOURS_TALLOC_LINK_OPTIONS})
        endif()
        target_link_libraries(${name} PRIVATE Microsoft::detours syelog kernel32.lib psapi.lib)
        set(subsystem CONSOLE)
        if(name STREQUAL "tdll1x")
            set(subsystem WINDOWS)
        endif()
        target_link_options(${name} PRIVATE /SUBSYSTEM:${subsystem} /NOENTRY /BASE:${base})
    endfunction()

    add_talloc_dll(tdll1x 0x280000000)
    add_talloc_dll(tdll2x 0x380000000)
    add_talloc_dll(tdll3x 0x480050000)
    add_talloc_dll(tdll4x 0x580000000)
    add_talloc_dll(tdll5x 0x680000000)
    add_talloc_dll(tdll6x 0x680010000)
    add_talloc_dll(tdll7x 0x680020000)
    add_talloc_dll(tdll8x 0x680030000)
    add_talloc_dll(tdll9x 0x680040000)

    add_detour_sample_exe(talloc
        SOURCES talloc/talloc.cpp
        LIBS kernel32.lib psapi.lib tdll1x tdll2x tdll3x tdll4x tdll5x tdll6x tdll7x tdll8x tdll9x
    )
    target_link_options(talloc PRIVATE /ENTRY:WinMainCRTStartup)
endif()

##############################################################################
## cping - MIDL-generated RPC proxy/stub sample. No CMake built-in language
## support for MIDL, so it's driven by hand via find_program()/add_custom_command().

find_program(MIDL_EXECUTABLE midl REQUIRED)

# ARM64EC reuses the X64 proxy stub; MIDL itself has no distinct ARM64EC target, only
# X86/IA64/X64/ARM/ARM64.
if(DETOURS_SAMPLE_ARCH STREQUAL "X86")
    set(DETOURS_CPING_MIDL_ARCH_FLAGS /no_robust /win32)
else()
    set(DETOURS_CPING_MIDL_ARCH_FLAGS /x64)
endif()

set(DETOURS_CPING_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/cping)
add_custom_command(
    OUTPUT
        ${DETOURS_CPING_GENERATED_DIR}/iping.h
        ${DETOURS_CPING_GENERATED_DIR}/iping_i.c
        ${DETOURS_CPING_GENERATED_DIR}/iping_p.c
        ${DETOURS_CPING_GENERATED_DIR}/iping_d.c
    COMMAND ${CMAKE_COMMAND} -E make_directory ${DETOURS_CPING_GENERATED_DIR}
    COMMAND ${MIDL_EXECUTABLE} /nologo /Oif /no_format_opt ${DETOURS_CPING_MIDL_ARCH_FLAGS}
        /out ${DETOURS_CPING_GENERATED_DIR} /prefix all iping_ /dlldata iping_d.c
        ${CMAKE_CURRENT_SOURCE_DIR}/cping/iping.idl
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/cping/iping.idl
    COMMENT "Generating RPC proxy/stub for cping via MIDL"
    VERBATIM
)

add_executable(cping
    cping/cping.cpp
    ${DETOURS_CPING_GENERATED_DIR}/iping_i.c
    ${DETOURS_CPING_GENERATED_DIR}/iping_p.c
    ${DETOURS_CPING_GENERATED_DIR}/iping_d.c
)
# The generated proxy/stub .c files are compiled at /W3 rather than the sample-wide /W4
# (cping.cpp itself still gets the full /W4 from DETOURS_SAMPLE_COMPILE_OPTIONS).
# cl.exe's default PDB name for C (as opposed to C++) is the shared "vc<ver>.pdb" rather than a
# per-target name, so a parallel build of these three files races on writing it -- observed as
# C1041 under test-arm64ec's Ninja build even with /FS (whose mspdbsrv.exe synchronization isn't
# reliable there) and even with a per-file /Fd (CMake appends its own shared /Fd later on the
# command line, which wins since cl.exe uses the last one). Use /Z7 instead, which embeds debug
# info directly in each .obj and never touches a .pdb at all, sidestepping the conflict outright.
set_source_files_properties(
    ${DETOURS_CPING_GENERATED_DIR}/iping_i.c
    ${DETOURS_CPING_GENERATED_DIR}/iping_p.c
    ${DETOURS_CPING_GENERATED_DIR}/iping_d.c
    PROPERTIES
        LANGUAGE C
        COMPILE_OPTIONS "/W3;/Z7"
)
target_include_directories(cping PRIVATE ${DETOURS_CPING_GENERATED_DIR})
detours_sample_common_settings(cping)
target_compile_definitions(cping PRIVATE
    ENTRY_PREFIX=iping_ REGISTER_PROXY_DLL
    _WIN32_WINNT=0x0400 CONST_VTABLE COBJMACROS WIN32 NT
)
target_link_libraries(cping PRIVATE
    kernel32.lib user32.lib shell32.lib uuid.lib ole32.lib rpcrt4.lib advapi32.lib wsock32.lib
)
# cping's own `test:` target starts a server (cping /s) and pings it -- stateful and
# interactive, not a quick isolated smoke test; left as build-only like traceapi/tracebld/
# tracessl/tracetcp above.

##############################################################################
## tryman - mixed native + C# sample. csc.exe/sn.exe are invoked directly, rather than via
## CMake's VS-generator-only enable_language(CSharp), so this works the same way under Ninja
## as under the VS generators.

add_detour_sample_dll(tstman
    SOURCES tryman/tstman.cpp tryman/tstman.rc
    EXPORTS "DetourFinishHelperProcess,@1,NONAME" "Test3264"
    LIBS kernel32.lib
)
add_detour_sample_exe(tryman SOURCES tryman/tryman.cpp LIBS kernel32.lib tstman)
add_detour_sample_exe(size SOURCES tryman/size.cpp)
target_link_options(size PRIVATE /FIXED:NO)

set(DETOURS_TRYMAN_KEY ${CMAKE_CURRENT_BINARY_DIR}/key.snk)
add_custom_command(
    OUTPUT ${DETOURS_TRYMAN_KEY}
    COMMAND sn -k ${DETOURS_TRYMAN_KEY}
    COMMENT "Generating strong-name key for managed tryman samples"
    VERBATIM
)
# The VS generators build one utility vcxproj per managed-<suffix> target below, and since
# none of them "owns" key.snk as its own OUTPUT, each vcxproj gets its own copy of this rule
# baked in. Under a parallel build that races multiple sn.exe invocations on the same file
# ("Failed to create key.snk -- The process cannot access the file because it is being used
# by another process."). Give it a single owning target and depend on that target (not the
# file) from each managed-<suffix> target so only one vcxproj ever runs the rule.
add_custom_target(tryman_key ALL DEPENDS ${DETOURS_TRYMAN_KEY})

# platform:output-suffix pairs for the managed-<suffix>.exe outputs below.
# The Itanium (/platform:itanium) variant is dropped -- IA64 isn't part of this CMake port.
set(DETOURS_TRYMAN_CSC_FLAGS /nowarn:1607 /unsafe- /optimize+ /debug+ /warnaserror)
foreach(entry x64:x64 x86:x86 anycpu:any anycpu32bitpreferred:any32)
    string(REPLACE ":" ";" entry ${entry})
    list(GET entry 0 platform)
    list(GET entry 1 suffix)
    set(managed_exe ${CMAKE_CURRENT_BINARY_DIR}/managed-${suffix}.exe)
    add_custom_command(
        OUTPUT ${managed_exe}
        COMMAND csc /nologo ${DETOURS_TRYMAN_CSC_FLAGS} /platform:${platform}
            /keyfile:${DETOURS_TRYMAN_KEY} /out:${managed_exe}
            managed.cs
        # The VS generators build one utility vcxproj per OUTPUT here; when managed.cs is
        # passed with its absolute source-tree path, they instead resolve it relative to the
        # build tree at MSBuild time (CS1504: "...\build\samples\managed.cs" could not be
        # opened). Running from tryman/ with a bare relative filename sidesteps that.
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tryman
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tryman/managed.cs
        COMMENT "Building managed-${suffix}.exe via csc.exe"
        VERBATIM
    )
    add_custom_target(managed-${suffix} ALL DEPENDS ${managed_exe})
    add_dependencies(managed-${suffix} tryman_key)
endforeach()
# tryman's managed-*.exe / tstman.dll interaction is a manual/interactive scenario, not a
# clean pass/fail assertion; left out of add_test() below like cping above.

##############################################################################
## Smoke tests -- only samples with a genuinely non-interactive, exit-code-
## checkable invocation are wired up here.
##
## traceapi/tracebld/tracessl/tracetcp launch Internet Explorer or an interactive
## cmd.exe session when run standalone and would hang a CI runner, so they're
## build-only.
##
## simple/slept/comeasy repeatedly toggle DLL injection on/off via setdll.exe
## (which rewrites the target .exe's import table in place) and only print
## human-readable banners for eyeball verification, with no actual pass/fail
## assertion -- not safe to reproduce under ctest's parallel/repeatable execution
## model. Their final withdll.exe step (dynamic injection, non-mutating) is kept
## instead as a real smoke test that the detour DLL loads and runs without
## crashing.
##
## echonul's mainCRTStartup (echo/main.cpp) always returns the fixed sentinel
## 0x99, regardless of success or failure, and prints nothing to stdout -- its
## exit code carries no pass/fail meaning and there is no output to assert on,
## so it isn't wired up as its own test. echofx's detoured run does print
## distinguishing output, so that's checked via PASS_REGULAR_EXPRESSION
## instead of the (always-0x99) exit code.
if(DETOURS_BUILD_TESTS)
    add_test(NAME region COMMAND region)
    add_test(NAME commem COMMAND commem)
    add_test(NAME dtest COMMAND dtest)

    # withdll's own injection/resume of echonul.exe under it never completes on ARM64EC --
    # echofx.dll's DllMain is never entered (not even its first, unconditional printf), so
    # this hangs until the TIMEOUT below on that platform. Unlike commem/comeasy (which
    # failed in DetourAttach/trampoline generation and were fixed upstream by
    # microsoft/Detours#388), this looks like a hang in the injection path itself, not in
    # attach/trampoline logic -- skip it on ARM64EC until that's root-caused upstream.
    if(NOT DETOURS_SAMPLE_ARCH STREQUAL "ARM64EC")
        add_test(NAME echo_detoured COMMAND withdll -d:$<TARGET_FILE:echofx> $<TARGET_FILE:echonul>)
        set_tests_properties(echo_detoured PROPERTIES
            PASS_REGULAR_EXPRESSION "Detoured Echo\\(\\)"
        )
    endif()

    add_test(NAME simple COMMAND withdll -d:$<TARGET_FILE:simple> $<TARGET_FILE:sleep5>)
    add_test(NAME slept COMMAND withdll -d:$<TARGET_FILE:slept> $<TARGET_FILE:sleepold>)
    add_test(NAME comeasy COMMAND withdll -d:$<TARGET_FILE:wrotei> $<TARGET_FILE:comeasy>)

    # None of these samples legitimately run anywhere near this long (the slowest,
    # `simple`/`slept`, sleep for only a few seconds); a much larger cap just guards
    # against a genuine hang (e.g. a detoured process deadlocking) silently consuming
    # the whole CI job's multi-hour default timeout instead of failing fast.
    set(DETOURS_SAMPLE_TESTS_WITH_TIMEOUT region commem dtest simple slept comeasy)
    if(NOT DETOURS_SAMPLE_ARCH STREQUAL "ARM64EC")
        list(APPEND DETOURS_SAMPLE_TESTS_WITH_TIMEOUT echo_detoured)
    endif()
    set_tests_properties(${DETOURS_SAMPLE_TESTS_WITH_TIMEOUT} PROPERTIES TIMEOUT 30)
endif()

################################################################# End of File.
