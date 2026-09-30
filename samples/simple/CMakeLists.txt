CMAKE_MINIMUM_REQUIRED(VERSION 3.10)
PROJECT(simple LANGUAGES C CXX)

# TODO: Exporting all functions sounds not quite good,
# but since I dont't want to change the original source code,
# this is the only two options ——
# another one is setting CXX_FLAGS /export switch manually,
# which is also not clean enough.
SET(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

ADD_LIBRARY(simple SHARED "simple.cpp" "simple.rc")
TARGET_LINK_LIBRARIES(simple PUBLIC detours_static)
TARGET_COMPILE_DEFINITIONS(simple PUBLIC ${DETOURS_COMPILE_DEFINITIONS})
TARGET_COMPILE_OPTIONS(simple PUBLIC ${DETOURS_COMPILE_OPTIONS})

ADD_EXECUTABLE(sleep5 "sleep5.cpp")
TARGET_COMPILE_DEFINITIONS(sleep5 PUBLIC ${DETOURS_COMPILE_DEFINITIONS})
TARGET_COMPILE_OPTIONS(sleep5 PUBLIC ${DETOURS_COMPILE_OPTIONS})