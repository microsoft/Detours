CMAKE_MINIMUM_REQUIRED(VERSION 3.10)
PROJECT(tryman LANGUAGES C CXX CSharp)

# TODO: Exporting all functions sounds not quite good,
# but since I dont't want to change the original source code,
# this is the only two options ——
# another one is setting CXX_FLAGS /export switch manually,
# which is also not clean enough.
SET(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

ADD_EXECUTABLE(size "size.cpp")
TARGET_LINK_LIBRARIES(size PUBLIC detours_static)
TARGET_COMPILE_DEFINITIONS(size PUBLIC ${DETOURS_COMPILE_DEFINITIONS})
TARGET_COMPILE_OPTIONS(size PUBLIC ${DETOURS_COMPILE_OPTIONS})

ADD_LIBRARY(tstman SHARED "tstman.cpp" "tstman.rc")
TARGET_LINK_LIBRARIES(tstman PUBLIC detours_static)
TARGET_COMPILE_DEFINITIONS(tstman PUBLIC ${DETOURS_COMPILE_DEFINITIONS})
TARGET_COMPILE_OPTIONS(tstman PUBLIC ${DETOURS_COMPILE_OPTIONS})

ADD_EXECUTABLE(tryman "tryman.cpp")
TARGET_LINK_LIBRARIES(tryman PUBLIC detours_static)
TARGET_LINK_LIBRARIES(tryman PUBLIC tstman)
TARGET_COMPILE_DEFINITIONS(tryman PUBLIC ${DETOURS_COMPILE_DEFINITIONS})
TARGET_COMPILE_OPTIONS(tryman PUBLIC ${DETOURS_COMPILE_OPTIONS})

# For Managed part
ADD_EXECUTABLE(tryman_managed "managed.cs")
SET_PROPERTY(TARGET tryman_managed PROPERTY VS_DOTNET_TARGET_FRAMEWORK_VERSION "v4.6.1")
SET_PROPERTY(TARGET tryman_managed PROPERTY WIN32_EXECUTABLE TRUE)
set_property(TARGET tryman_managed PROPERTY VS_DOTNET_REFERENCES
    "Microsoft.CSharp"
    "System"
    "System.Core")