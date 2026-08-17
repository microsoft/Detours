##############################################################################
##
##  Consumer project proving that an installed Detours package is usable via
##  find_package(Detours).
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

cmake_minimum_required(VERSION 3.28.3)

project(DetoursFindPackageConsumer LANGUAGES CXX)

find_package(Detours REQUIRED CONFIG)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE Microsoft::detours)

if(MSVC)
    target_compile_options(consumer PRIVATE /W4 /WX)
    target_link_options(consumer PRIVATE /WX)
endif()
