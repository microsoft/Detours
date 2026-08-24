CMAKE_MINIMUM_REQUIRED(VERSION 3.10)
PROJECT(tracebld LANGUAGES C CXX)

# TODO: Exporting all functions sounds not quite good,
# but since I dont't want to change the original source code,
# this is the only two options ——
# another one is setting CXX_FLAGS /export switch manually,
# which is also not clean enough.
SET(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

INCLUDE_DIRECTORIES("${CMAKE_CURRENT_LIST_DIR}")
INCLUDE_DIRECTORIES("${CMAKE_CURRENT_LIST_DIR}/../syelog")

FILE(GLOB src
    ${CMAKE_CURRENT_LIST_DIR}/*.cpp
	${CMAKE_CURRENT_LIST_DIR}/*.rc
)

ADD_LIBRARY(tracebld SHARED ${src})
TARGET_LINK_LIBRARIES(tracebld PUBLIC detours_static)

TARGET_COMPILE_DEFINITIONS(tracebld PUBLIC ${DETOURS_COMPILE_DEFINITIONS})
TARGET_COMPILE_OPTIONS(tracebld PUBLIC ${DETOURS_COMPILE_OPTIONS})