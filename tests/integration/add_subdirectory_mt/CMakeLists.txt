##############################################################################
##
##  Consumer project proving that the Detours source tree is usable via
##  add_subdirectory() when the consumer matches Detours' own /MT runtime
##  library setting (see root CMakeLists.txt). Compare with
##  ../add_subdirectory_dll, which deliberately differs.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

cmake_minimum_required(VERSION 3.28.3)

project(DetoursAddSubdirectoryMTConsumer LANGUAGES CXX)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../../.." detours)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE Microsoft::detours)

if(MSVC)
    target_compile_options(consumer PRIVATE /W4 /WX)
    target_link_options(consumer PRIVATE /WX)
endif()
