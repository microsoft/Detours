##############################################################################
##
##  Configures and builds one of the consumer smoke-test projects out of
##  process, mirroring the outer build's generator/platform/config.
##
##  Expected -D arguments: SOURCE_DIR, BINARY_DIR, GENERATOR, CONFIG, and
##  optionally PLATFORM and PREFIX_PATH.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

set(configure_args -S "${SOURCE_DIR}" -B "${BINARY_DIR}" -G "${GENERATOR}")

if(PLATFORM)
    list(APPEND configure_args -A "${PLATFORM}")
endif()

if(PREFIX_PATH)
    list(APPEND configure_args "-DCMAKE_PREFIX_PATH=${PREFIX_PATH}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" ${configure_args}
    RESULT_VARIABLE configure_result
)
if(NOT configure_result EQUAL 0)
    message(FATAL_ERROR "Configuring ${SOURCE_DIR} failed")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${BINARY_DIR}" --config "${CONFIG}"
    RESULT_VARIABLE build_result
)
if(NOT build_result EQUAL 0)
    message(FATAL_ERROR "Building ${SOURCE_DIR} failed")
endif()
