##############################################################################
##
##  Consumer project proving that the Detours source tree is usable via
##  add_subdirectory() when the consumer's MSVC runtime library setting
##  deliberately differs from Detours' own /MT (see root CMakeLists.txt) --
##  a consumer's runtime library choice is independent of Detours', and
##  pulling in a /MT-only static lib via add_subdirectory() doesn't force a
##  /MD consumer target to downgrade, or produce a linker warning/error, as
##  long as the consumer doesn't itself pull in CRT/STL headers that embed a
##  conflicting RuntimeLibrary detect_mismatch claim. Compare with
##  ../add_subdirectory_mt, which matches instead.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

cmake_minimum_required(VERSION 3.28.3)

project(DetoursAddSubdirectoryDLLConsumer LANGUAGES CXX)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../../.." detours)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE Microsoft::detours)

if(MSVC)
    target_compile_options(consumer PRIVATE /W4 /WX)
    target_link_options(consumer PRIVATE /WX)
endif()
