##############################################################################
##
##  CMakeLists.txt for the detours library.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

target_sources(detours
    PRIVATE
        creatwth.cpp
        detours.cpp
        disasm.cpp
        disolarm.cpp
        disolarm64.cpp
        disolia64.cpp
        disolx64.cpp
        disolx86.cpp
        image.cpp
        modules.cpp
    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
        FILES detours.h detver.h
)

target_compile_definitions(detours PRIVATE
    WIN32_LEAN_AND_MEAN     # excludes rarely-used Windows API surface (sockets, GDI, ...) from <windows.h> to cut compile time and avoid symbol collisions
    _WIN32_WINNT=0x0501     # declares the oldest Windows API level Detours' headers may assume, since target processes it attaches to may run very old Windows builds
    $<$<CONFIG:Debug>:DETOUR_DEBUG=1>    # enables verbose DETOUR_TRACE diagnostics (see detours.cpp) in Debug builds only
)

if(MSVC)
    target_compile_options(detours PRIVATE
        /W4
        /we4777 /we4800     # format-string and BOOL-truncation bugs are easy to introduce against the raw WinAPI; promote them to hard errors too
        /Gy     # function-level linking (not a CMake default -- checked Windows-MSVC.cmake)
        /Zl     # omit the default library name so consumers pick their own CRT
        /Od     # detours patches raw machine code; optimized codegen has broken this historically
    )
endif()
