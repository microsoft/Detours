##############################################################################
##
##  CMakeLists.txt for the Detours unit tests.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

add_executable(unittests
    corruptor.cpp
    main.cpp
    payload.cpp
    process_helpers.cpp
    test_image_api.cpp
    test_module_api.cpp
)

# corruptor.cpp deliberately triggers hardware exceptions to exercise the
# image API's error paths; without this define, Catch's vectored exception
# handler intercepts them and crashes the suite (exit 139) instead of
# reporting a clean test failure.
target_compile_definitions(unittests PRIVATE CATCH_CONFIG_NO_WINDOWS_SEH)

# /EHsc (Catch2's assertion macros are implemented via C++ exceptions) is
# omitted here: CMake's MSVC defaults already put it in CMAKE_CXX_FLAGS for
# every target, confirmed via CMakeCache.txt (CMAKE_CXX_FLAGS:STRING=/DWIN32
# /D_WINDOWS /EHsc), so restating it would just be a duplicate flag.
#
# Only real MSVC (cl.exe) is supported today; this is scoped under if(MSVC)
# rather than applied unconditionally so a follow-up PR can add clang-cl/
# MinGW-w64 support here without restructuring this file.
if(MSVC)
    target_compile_options(unittests PRIVATE
        /W4 /we4777 /we4800 /Od   # same warning/codegen policy as the detours library (see src/CMakeLists.txt)
    )
endif()

target_link_libraries(unittests PRIVATE
    Microsoft::detours
    kernel32.lib    # CreateProcessW() in process_helpers.cpp
)

add_test(NAME unittests COMMAND unittests --reporter console --success --durations yes)

# Guards against DETOURS_VERSION (src/detours.h) drifting from the project's own
# VERSION (root CMakeLists.txt) -- the two are maintained by hand in separate files,
# so nothing else catches them silently going out of sync.
add_executable(version_check version_check.cpp)
target_link_libraries(version_check PRIVATE Microsoft::detours)
target_compile_definitions(version_check PRIVATE
    DETOURS_EXPECTED_VERSION=0x${PROJECT_VERSION_MAJOR}c${PROJECT_VERSION_MINOR}c${PROJECT_VERSION_PATCH}
)
add_test(NAME version_check COMMAND version_check)

# Each integration test spawns a nested CMake configure+build, so they're
# noticeably slower than the unit tests; leave them opt-in for local
# development and enable them in CI.
option(DETOURS_BUILD_INTEGRATION_TESTS "Build the find_package()/add_subdirectory() consumer smoke tests" OFF)

if(DETOURS_BUILD_INTEGRATION_TESTS)
    add_subdirectory(integration)
endif()
