##############################################################################
##
##  CTest smoke tests proving that downstream projects can consume Detours
##  both via find_package(Detours) (against an installed package) and via
##  add_subdirectory() (built straight from this source tree).
##
##  Each scenario is a tiny standalone CMake project under this directory,
##  configured and built out-of-process by run_consumer.cmake using the same
##  generator/platform/config as the outer build.
##
##  Microsoft Research Detours Package
##
##  Copyright (c) Microsoft Corporation.  All rights reserved.
##

add_test(NAME integration.add_subdirectory_mt
    COMMAND ${CMAKE_COMMAND}
        "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/add_subdirectory_mt"
        "-DBINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_mt"
        "-DGENERATOR=${CMAKE_GENERATOR}"
        "-DPLATFORM=${CMAKE_GENERATOR_PLATFORM}"
        "-DCONFIG=$<CONFIG>"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/run_consumer.cmake"
)

add_test(NAME integration.add_subdirectory_dll
    COMMAND ${CMAKE_COMMAND}
        "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/add_subdirectory_dll"
        "-DBINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/add_subdirectory_dll"
        "-DGENERATOR=${CMAKE_GENERATOR}"
        "-DPLATFORM=${CMAKE_GENERATOR_PLATFORM}"
        "-DCONFIG=$<CONFIG>"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/run_consumer.cmake"
)

if(DETOURS_INSTALL)
    set(_detours_stage_dir "${CMAKE_CURRENT_BINARY_DIR}/stage")

    # find_package(Detours) needs a real installed package to find, so stage
    # one in an isolated prefix under the build tree rather than touching
    # whatever CMAKE_INSTALL_PREFIX the outer build is configured with.
    add_test(NAME integration.stage_install
        COMMAND ${CMAKE_COMMAND} --install "${CMAKE_BINARY_DIR}" --config $<CONFIG> --prefix "${_detours_stage_dir}"
    )
    set_tests_properties(integration.stage_install PROPERTIES
        FIXTURES_SETUP DetoursStageInstall
    )

    add_test(NAME integration.find_package
        COMMAND ${CMAKE_COMMAND}
            "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/find_package"
            "-DBINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/find_package"
            "-DGENERATOR=${CMAKE_GENERATOR}"
            "-DPLATFORM=${CMAKE_GENERATOR_PLATFORM}"
            "-DCONFIG=$<CONFIG>"
            "-DPREFIX_PATH=${_detours_stage_dir}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/run_consumer.cmake"
    )
    set_tests_properties(integration.find_package PROPERTIES
        FIXTURES_REQUIRED DetoursStageInstall
    )
endif()
