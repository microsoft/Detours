##############################################################################
##
##  Samples README File
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

This README file describes how to set up your build environment, build
samples, and run tests.

BUILD ENVIRONMENT:
==================
We assume that you have a version of the Visual Studio IDE installed.  You can
download a free copy of the Visual Studio IDE from
https://visualstudio.microsoft.com.  During Visual Studio installation, make
sure that C/C++ tools are installed and that the Windows SDK is installed.

Clone the Detours git repo to a directory on your machine.  Choose a directory
that does not have spaces in the full path name.

BUILDING:
=========
Open a Developer Command Prompt for VS, or run vcvarsall.bat for your target
architecture, so that cmake can find the MSVC toolset. From the root of your
git repo, configure and build with the samples option turned on:

    cmake -S . -B build -DDETOURS_BUILD_SAMPLES=ON
    cmake --build build

Note that you must build setdll and syslog in order to use many of the
other sample programs; both are built automatically as part of the samples
target above.

INSTALLING AND BUILDING VIA VCPKG:
==================================
You can download and install detours using the vcpkg(https://github.com/Microsoft/vcpkg) dependency manager:

    git clone https://github.com/Microsoft/vcpkg.git
    cd vcpkg
    ./bootstrap-vcpkg.sh
    ./vcpkg integrate install
    vcpkg install detours
    
The detours port in vcpkg is kept up to date by Microsoft team members and community contributors. If the version is out of date, please create an issue or pull request(https://github.com/Microsoft/vcpkg) on the vcpkg repository.

TESTING:
========
A number of the samples have a test, registered with ctest, that demonstrates
their usage. With very few exceptions, all of the executables also accept a
"/?" command to display a usage message.

To run the sample tests, configure with tests enabled as well and use ctest:

    cmake -S . -B build -DDETOURS_BUILD_SAMPLES=ON -DDETOURS_BUILD_TESTS=ON
    cmake --build build
    ctest --test-dir build

COMMENTS:
=========
The trace* samples log their output through the syelogd.exe daemon and hook
CreateProcessW to load themselves into any child processes.  For example,
typing "withdll -d:traceapi.dll cmd.exe" will create a command shell under
which all processes log their API calls through traceapi.dll.
