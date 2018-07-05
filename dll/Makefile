##############################################################################
##
##  Makefile for Detours Test Programs.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##
##  Note:
##    syelog, setdll, and withdll must be built first because a number of the
##    other samples depend on them.
##

ROOT=..
!include .\common.mak

##############################################################################

all:
    cd "$(MAKEDIR)\corehook"
    @$(MAKE) /NOLOGO /$(MAKEFLAGS)
    
clean:
    cd "$(MAKEDIR)\corehook"
    @$(MAKE) /NOLOGO /$(MAKEFLAGS) clean
    cd "$(MAKEDIR)"
    -rmdir lib32 2>nul
    -rmdir lib64 2>nul
    -rmdir include 2>nul

realclean:
    cd "$(MAKEDIR)\corehook"
    @$(MAKE) /NOLOGO /$(MAKEFLAGS) realclean
    cd "$(MAKEDIR)"
    -rmdir lib32 2>nul
    -rmdir lib64 2>nul
    -rmdir include 2>nul

test:
    cd "$(MAKEDIR)\corehook"
    @$(MAKE) /NOLOGO /$(MAKEFLAGS) test

    cd "$(MAKEDIR)"

##
################################################################# End of File.
