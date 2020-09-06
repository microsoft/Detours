##############################################################################
##
##  Makefile for Detours Test Programs.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

!include ..\common.mak

LIBS=$(LIBS) kernel32.lib
CFLAGS=$(CFLAGS) /EHsc

all: dirs \
    $(BIND)\payload.exe \
    $(BIND)\payloadtarget.exe

clean:
    -del *~ 2>nul
    -del $(BIND)\payload.* 2>nul
    -del $(BIND)\payloadtarget.* 2>nul
    -rmdir /q /s $(OBJD) 2>nul

realclean: clean
    -rmdir /q /s $(OBJDS) 2>nul

dirs:
    @if not exist $(BIND) mkdir $(BIND) && echo.   Created $(BIND)
    @if not exist $(OBJD) mkdir $(OBJD) && echo.   Created $(OBJD)

$(OBJD)\payload.obj : payload.cpp

$(BIND)\payload.exe : $(OBJD)\payload.obj $(DEPS)
    link\
        /SUBSYSTEM:CONSOLE\
        $(LINKFLAGS)\
        $(LIBS)\
        /PDB:"$(@R).pdb"\
        /OUT:"$@"\
        $**\

$(OBJD)\payloadtarget.obj : payloadtarget.cpp

$(BIND)\payloadtarget.exe : $(OBJD)\payloadtarget.obj $(DEPS)
    link\
        /SUBSYSTEM:CONSOLE\
        $(LINKFLAGS)\
        $(LIBS)\
        /PDB:"$(@R).pdb"\
        /OUT:"$@"\
        $**\

##############################################################################

test: $(BIND)\payload.exe $(BIND)\payloadtarget.exe
    $(BIND)\payload.exe

################################################################# End of File.
