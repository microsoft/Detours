##############################################################################
##
##  Samples README File
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

BUILDING:
=========
To build the sample applications, type "nmake" in the samples directory.
Note that you must build setdll and syslog in order to use many of the
other sample programs.

COMMENTS:
=========
Each of the sample directories has a test, which can be invoked by typing
"nmake test", to demonstrate the usage of the sample.  With very few
exceptions, all of the executables also accept a "/?" command to display a
usage message.

The trace* samples log their output through the syelogd.exe daemon and hook
CreateProcessW to load themselves into any child processes.  For example,
typing "withdll -d:traceapi.dll cmd.exe" will create a command shell under
which all processes log their API calls through traceapi.dll.
