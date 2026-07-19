# Lightweight tests (see test_util.hpp for why there's no third-party test
# framework here). Each test_*.cpp is its own executable, registered with
# CTest below; `ctest --output-on-failure` from the build directory runs
# them all.

add_executable(test_protocol test_protocol.cpp)
target_include_directories(test_protocol PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_protocol PRIVATE epx::epx)
add_test(NAME protocol COMMAND test_protocol)

add_executable(test_lifecycle test_lifecycle.cpp)
target_link_libraries(test_lifecycle PRIVATE epx::epx)
add_test(NAME lifecycle COMMAND test_lifecycle)

add_executable(test_streaming test_streaming.cpp)
target_link_libraries(test_streaming PRIVATE epx::epx)
add_test(NAME streaming COMMAND test_streaming)

add_executable(test_shutdown_hooks test_shutdown_hooks.cpp)
target_link_libraries(test_shutdown_hooks PRIVATE epx::epx)
add_test(NAME shutdown_hooks COMMAND test_shutdown_hooks)

add_executable(test_access test_access.cpp)
target_include_directories(test_access PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_access PRIVATE epx::epx)
add_test(NAME access COMMAND test_access)

add_executable(test_limits test_limits.cpp)
target_link_libraries(test_limits PRIVATE epx::epx)
add_test(NAME limits COMMAND test_limits)

add_executable(test_topic test_topic.cpp)
target_link_libraries(test_topic PRIVATE epx::epx)
add_test(NAME topic COMMAND test_topic)

add_executable(test_registry test_registry.cpp)
target_link_libraries(test_registry PRIVATE epx::epx)
add_test(NAME registry COMMAND test_registry)

add_executable(test_rotation test_rotation.cpp)
target_link_libraries(test_rotation PRIVATE epx::epx)
add_test(NAME rotation COMMAND test_rotation)

# The C ABI suite: the same end-to-end coverage, driven from pure C
# through libepx_c the way every language binding consumes EPX.
if(EPX_BUILD_CAPI)
    add_executable(test_c_api test_c_api.c)
    target_link_libraries(test_c_api PRIVATE epx::epx_c)
    add_test(NAME c_api COMMAND test_c_api)
endif()

# lifecycle/streaming/shutdown_hooks open real sockets and spawn a
# Host+Client in-process; isolate each from the developer's real ~/.epx
# and runtime dir, and from each other, by pointing HOME/XDG_RUNTIME_DIR
# somewhere private to each test. Deliberately NOT under
# CMAKE_CURRENT_BINARY_DIR: Unix domain socket paths are capped at ~100
# bytes by the kernel (sockaddr_un::sun_path), and a build directory
# nested a few levels deep (easy to end up with in CI, or on any system
# with a long checkout path) can blow past that on its own before EPX's
# own registry/socket subpath is even added — transport_posix.cpp throws
# a clear "socket path too long" error rather than silently truncating,
# but the fix here is simply to keep test state short-and-flat under the
# OS temp dir instead. Also cap runtime — a hang (e.g. a shutdown
# regression) should FAIL, not stall the whole suite.
if(WIN32)
    set(epx_test_tmp_root "$ENV{TEMP}/epx-ctest")
else()
    set(epx_test_tmp_root "/tmp/epx-ctest")
endif()
foreach(t lifecycle streaming shutdown_hooks access limits topic registry rotation c_api)
    set(sandbox "${epx_test_tmp_root}/${t}")
    file(MAKE_DIRECTORY "${sandbox}/run")
    set_tests_properties(${t} PROPERTIES
        ENVIRONMENT "HOME=${sandbox};XDG_RUNTIME_DIR=${sandbox}/run"
        TIMEOUT 30
    )
endforeach()
