##############################################################################
##
##  Makefile for Detours shared library.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

!include .\common.mak

LIBS=$(LIBS) kernel32.lib

##############################################################################

all: dirs \
    $(BIND)\detours.dll \
!IF $(DETOURS_SOURCE_BROWSING)==1
    $(OBJD)\libdetours.bsc \
!ENDIF
    option

clean:
    -del *~ 2>nul
    -del $(BIND)\detours.* 2>nul
    -rmdir /q /s $(OBJD) 2>nul

realclean: clean
    -rmdir /q /s $(OBJDS) 2>nul

##############################################################################

dirs:
    @if not exist $(BIND) mkdir $(BIND) && echo.   Created $(BIND)
    @if not exist $(OBJD) mkdir $(OBJD) && echo.   Created $(OBJD)

$(OBJD)\libdetours.obj : libdetours.cpp

$(BIND)\detours.dll : $(OBJD)\libdetours.obj $(DEPS)
    cl $(CFLAGS) /Fe$@ /Fd$(@R).pdb $(OBJD)\libdetours.obj \
        /link /DLL $(LINKFLAGS) $(LIBS) /DEF:detours.def

$(OBJD)\libdetours.bsc : $(OBJD)\libdetours.obj
    bscmake /v /n /o $@ $(OBJD)\libdetours.sbr

############################################### Install non-bit-size binaries.

option:

##############################################################################

test: all

debug: all

################################################################# End of File.
