# FindSodium.cmake — locate libsodium and expose it as an imported target.
#
# This module first tries pkg-config (covers apt/dnf/pacman/brew installs
# out of the box), then falls back to a manual find_path/find_library
# search (covers vcpkg and other setups without a .pc file).
#
# Defines:
#   Sodium_FOUND
#   Sodium::sodium   -- imported target; link against this, nothing else.
#
# Usage (see root CMakeLists.txt):
#   list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
#   find_package(Sodium REQUIRED)
#   target_link_libraries(mytarget PRIVATE Sodium::sodium)

include(FindPackageHandleStandardArgs)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PC_SODIUM QUIET libsodium)
endif()

find_path(Sodium_INCLUDE_DIR
    NAMES sodium.h
    HINTS ${PC_SODIUM_INCLUDE_DIRS}
)

find_library(Sodium_LIBRARY
    NAMES sodium libsodium
    HINTS ${PC_SODIUM_LIBRARY_DIRS}
)

find_package_handle_standard_args(Sodium
    REQUIRED_VARS Sodium_LIBRARY Sodium_INCLUDE_DIR
    VERSION_VAR PC_SODIUM_VERSION
)

if(Sodium_FOUND AND NOT TARGET Sodium::sodium)
    add_library(Sodium::sodium UNKNOWN IMPORTED)
    set_target_properties(Sodium::sodium PROPERTIES
        IMPORTED_LOCATION "${Sodium_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${Sodium_INCLUDE_DIR}"
    )
endif()

mark_as_advanced(Sodium_INCLUDE_DIR Sodium_LIBRARY)
