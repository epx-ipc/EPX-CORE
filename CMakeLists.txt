cmake_minimum_required(VERSION 3.16)

project(epx
    VERSION 2.1.0
    DESCRIPTION "EPX — Encrypted Process eXchange: local, authenticated, end-to-end encrypted IPC"
    HOMEPAGE_URL "https://github.com/epx-ipc/EPX-CORE"
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

# Top-level-only options: if EPX is add_subdirectory()'d into a larger
# project, don't build its examples/tests or pollute the parent's install()
# unless the parent explicitly asks.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(EPX_IS_TOP_LEVEL ON)
else()
    set(EPX_IS_TOP_LEVEL OFF)
endif()

option(EPX_BUILD_EXAMPLES "Build the example programs (expose_demo, client_demo, chat)" ${EPX_IS_TOP_LEVEL})
option(EPX_BUILD_TESTS    "Build and register the test suite (CTest)"                    ${EPX_IS_TOP_LEVEL})
option(EPX_BUILD_CLI      "Build the epx command-line tool (epx list / epx describe)"    ${EPX_IS_TOP_LEVEL})
option(EPX_BUILD_CAPI     "Build libepx_c, the stable C ABI every language binding links against" ON)
option(EPX_INSTALL        "Generate an install() target for the library and headers"     ${EPX_IS_TOP_LEVEL})

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(Sodium REQUIRED)

# --- library -----------------------------------------------------------
add_library(epx STATIC
    src/protocol.cpp
    src/credentials.cpp
    src/crypto.cpp
    src/registry.cpp
    src/keystore.cpp
    src/framing.cpp
    src/handshake.cpp
    src/host.cpp
    src/client.cpp
    src/identity.cpp
    src/init.cpp
    $<$<PLATFORM_ID:Windows>:src/transport_win.cpp>
    $<$<PLATFORM_ID:Windows>:src/paths_win.cpp>
    $<$<NOT:$<PLATFORM_ID:Windows>>:src/transport_posix.cpp>
    $<$<NOT:$<PLATFORM_ID:Windows>>:src/paths_posix.cpp>
)
add_library(epx::epx ALIAS epx)

# Generates include/epx/version.hpp from version.hpp.in, keeping it always
# in sync with the `project(epx VERSION ...)` line above rather than
# risking a hand-maintained copy drifting out of date.
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/epx/version.hpp.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated_include/epx/version.hpp
    @ONLY
)

target_include_directories(epx PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated_include>
    $<INSTALL_INTERFACE:include>
)
target_include_directories(epx PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(epx PUBLIC Sodium::sodium)

if(WIN32)
    target_link_libraries(epx PUBLIC advapi32 shell32)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(epx PUBLIC Threads::Threads)
endif()

target_compile_options(epx PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
)

set_target_properties(epx PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# --- C ABI (the product every language binding links against) ------------
if(EPX_BUILD_CAPI)
    # The static C++ core folds into this shared library, so bindings
    # depend on the one libepx_c artifact (plus libsodium, transitively).
    set_target_properties(epx PROPERTIES POSITION_INDEPENDENT_CODE ON)

    add_library(epx_c SHARED src/c_api.cpp)
    add_library(epx::epx_c ALIAS epx_c)
    target_include_directories(epx_c PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    target_link_libraries(epx_c PRIVATE epx::epx)
    target_compile_definitions(epx_c PRIVATE EPX_C_BUILDING=1)
    set_target_properties(epx_c PROPERTIES
        VERSION   ${PROJECT_VERSION}
        SOVERSION 1                    # tracks EPX_C_ABI_VERSION, not the release
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )
    target_compile_options(epx_c PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic>
    )
endif()

# --- subprojects ---------------------------------------------------------
if(EPX_BUILD_CLI)
    add_executable(epx_cli tools/epx_cli.cpp)
    set_target_properties(epx_cli PROPERTIES OUTPUT_NAME epx)
    target_link_libraries(epx_cli PRIVATE epx::epx)
endif()

if(EPX_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(EPX_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# --- install / packaging --------------------------------------------------
if(EPX_INSTALL)
    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)

    install(TARGETS epx
        EXPORT epxTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(EPX_BUILD_CAPI)
        install(TARGETS epx_c
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
    endif()
    if(EPX_BUILD_CLI)
        install(TARGETS epx_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()
    install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        PATTERN "*.in" EXCLUDE
    )
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/generated_include/epx/version.hpp
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/epx
    )

    install(EXPORT epxTargets
        FILE epxTargets.cmake
        NAMESPACE epx::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/epx
    )

    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/epxConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/epxConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/epx
    )
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/epxConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/epxConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/epxConfigVersion.cmake
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindSodium.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/epx
    )
endif()
