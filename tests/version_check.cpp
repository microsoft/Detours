//
//  DETOURS_VERSION (src/detours.h) and the VERSION passed to project() in the root
//  CMakeLists.txt are maintained by hand in two separate files; this confirms they
//  haven't drifted apart. DETOURS_EXPECTED_VERSION is derived from PROJECT_VERSION_MAJOR/
//  MINOR/PATCH by tests/CMakeLists.txt, using the same 0x<major>c<minor>c<patch> hex-literal
//  encoding as DETOURS_VERSION itself.
//

#include <windows.h>
#include "detours.h"
#include <cstdio>

int main()
{
    if (DETOURS_VERSION != DETOURS_EXPECTED_VERSION) {
        std::printf("DETOURS_VERSION (0x%x) does not match the CMake project VERSION-derived "
            "value (0x%x) -- update whichever one is stale.\n",
            DETOURS_VERSION, DETOURS_EXPECTED_VERSION);
        return 1;
    }
    return 0;
}
