# CMAKE_MINIMUM_REQUIRED(VERSION 3.10)
# PROJECT(slept LANGUAGES C CXX)

# INCLUDE_DIRECTORIES("${CMAKE_CURRENT_LIST_DIR}")

# # TODO: Exporting all functions sounds not quite good,
# # but since I dont't want to change the original source code,
# # this is the only two options ——
# # another one is setting CXX_FLAGS /export switch manually,
# # which is also not clean enough.
# SET(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

# ADD_LIBRARY(slept SHARED "dslept.cpp" "verify.cpp" "slept.rc")
# TARGET_LINK_LIBRARIES(slept PUBLIC detours_static)
# TARGET_COMPILE_DEFINITIONS(slept PUBLIC ${DETOURS_COMPILE_DEFINITIONS})
# TARGET_COMPILE_OPTIONS(slept PUBLIC ${DETOURS_COMPILE_OPTIONS})

# ADD_LIBRARY(dslept SHARED "slept.cpp" "verify.cpp")
# TARGET_LINK_LIBRARIES(dslept PUBLIC detours_static)
# TARGET_COMPILE_DEFINITIONS(dslept PUBLIC ${DETOURS_COMPILE_DEFINITIONS})
# TARGET_COMPILE_OPTIONS(dslept PUBLIC ${DETOURS_COMPILE_OPTIONS})

# ADD_EXECUTABLE(sleepold "sleepold.cpp" "verify.cpp")
# TARGET_COMPILE_DEFINITIONS(sleepold PUBLIC ${DETOURS_COMPILE_DEFINITIONS})
# TARGET_COMPILE_OPTIONS(sleepold PUBLIC ${DETOURS_COMPILE_OPTIONS})

# ADD_EXECUTABLE(sleepnew "sleepnew.cpp" "verify.cpp")
# TARGET_COMPILE_DEFINITIONS(sleepnew PUBLIC ${DETOURS_COMPILE_DEFINITIONS})
# TARGET_COMPILE_OPTIONS(sleepnew PUBLIC ${DETOURS_COMPILE_OPTIONS})

# ADD_EXECUTABLE(sleepbed "sleepbed.cpp" "verify.cpp")
# TARGET_COMPILE_DEFINITIONS(sleepbed PUBLIC ${DETOURS_COMPILE_DEFINITIONS})
# TARGET_COMPILE_OPTIONS(sleepbed PUBLIC ${DETOURS_COMPILE_OPTIONS})