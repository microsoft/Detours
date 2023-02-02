##############################################################################
##
##  Makefile for Detours Test Programs - Dump Imports
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

!include ..\common.mak

LIBS=$(LIBS) kernel32.lib

all: dirs \
    $(BIND)\callback.exe \
!IF $(DETOURS_SOURCE_BROWSING)==1
    $(OBJD)\callback.bsc \
!ENDIF

clean:
    -del *~ 2>nul
    -del $(BIND)\callback.* 2>nul
    -rmdir /q /s $(OBJD) 2>nul

realclean: clean
    -rmdir /q /s $(OBJDS) 2>nul

dirs:
    @if not exist $(BIND) mkdir $(BIND) && echo.   Created $(BIND)
    @if not exist $(OBJD) mkdir $(OBJD) && echo.   Created $(OBJD)

$(OBJD)\callback.obj : callback.cpp

$(BIND)\callback.exe : $(OBJD)\callback.obj $(DEPS)
    cl $(CFLAGS) /Fe$@ /Fd$(@R).pdb $(OBJD)\callback.obj \
        /link $(LINKFLAGS) $(LIBS) \
        /subsystem:console

$(OBJD)\callback.bsc : $(OBJD)\callback.obj
    bscmake /v /n /o $@ $(OBJD)\callback.sbr

##############################################################################

test: $(BIND)\callback.exe
    $(BIND)\callback.exe

################################################################# End of File.
