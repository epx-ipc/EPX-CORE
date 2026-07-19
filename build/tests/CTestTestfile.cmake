# CMake generated Testfile for 
# Source directory: /Users/neto/Desktop/EPX/EPX-CORE/tests
# Build directory: /Users/neto/Desktop/EPX/EPX-CORE/build/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(protocol "/Users/neto/Desktop/EPX/EPX-CORE/build/tests/test_protocol")
set_tests_properties(protocol PROPERTIES  _BACKTRACE_TRIPLES "/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;9;add_test;/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;0;")
add_test(lifecycle "/Users/neto/Desktop/EPX/EPX-CORE/build/tests/test_lifecycle")
set_tests_properties(lifecycle PROPERTIES  ENVIRONMENT "HOME=/tmp/epx-ctest/lifecycle;XDG_RUNTIME_DIR=/tmp/epx-ctest/lifecycle/run" TIMEOUT "30" _BACKTRACE_TRIPLES "/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;13;add_test;/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;0;")
add_test(streaming "/Users/neto/Desktop/EPX/EPX-CORE/build/tests/test_streaming")
set_tests_properties(streaming PROPERTIES  ENVIRONMENT "HOME=/tmp/epx-ctest/streaming;XDG_RUNTIME_DIR=/tmp/epx-ctest/streaming/run" TIMEOUT "30" _BACKTRACE_TRIPLES "/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;17;add_test;/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;0;")
add_test(shutdown_hooks "/Users/neto/Desktop/EPX/EPX-CORE/build/tests/test_shutdown_hooks")
set_tests_properties(shutdown_hooks PROPERTIES  ENVIRONMENT "HOME=/tmp/epx-ctest/shutdown_hooks;XDG_RUNTIME_DIR=/tmp/epx-ctest/shutdown_hooks/run" TIMEOUT "30" _BACKTRACE_TRIPLES "/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;21;add_test;/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;0;")
add_test(access "/Users/neto/Desktop/EPX/EPX-CORE/build/tests/test_access")
set_tests_properties(access PROPERTIES  ENVIRONMENT "HOME=/tmp/epx-ctest/access;XDG_RUNTIME_DIR=/tmp/epx-ctest/access/run" TIMEOUT "30" _BACKTRACE_TRIPLES "/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;26;add_test;/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;0;")
add_test(limits "/Users/neto/Desktop/EPX/EPX-CORE/build/tests/test_limits")
set_tests_properties(limits PROPERTIES  ENVIRONMENT "HOME=/tmp/epx-ctest/limits;XDG_RUNTIME_DIR=/tmp/epx-ctest/limits/run" TIMEOUT "30" _BACKTRACE_TRIPLES "/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;30;add_test;/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;0;")
add_test(topic "/Users/neto/Desktop/EPX/EPX-CORE/build/tests/test_topic")
set_tests_properties(topic PROPERTIES  ENVIRONMENT "HOME=/tmp/epx-ctest/topic;XDG_RUNTIME_DIR=/tmp/epx-ctest/topic/run" TIMEOUT "30" _BACKTRACE_TRIPLES "/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;34;add_test;/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;0;")
add_test(registry "/Users/neto/Desktop/EPX/EPX-CORE/build/tests/test_registry")
set_tests_properties(registry PROPERTIES  ENVIRONMENT "HOME=/tmp/epx-ctest/registry;XDG_RUNTIME_DIR=/tmp/epx-ctest/registry/run" TIMEOUT "30" _BACKTRACE_TRIPLES "/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;38;add_test;/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;0;")
add_test(rotation "/Users/neto/Desktop/EPX/EPX-CORE/build/tests/test_rotation")
set_tests_properties(rotation PROPERTIES  ENVIRONMENT "HOME=/tmp/epx-ctest/rotation;XDG_RUNTIME_DIR=/tmp/epx-ctest/rotation/run" TIMEOUT "30" _BACKTRACE_TRIPLES "/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;42;add_test;/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;0;")
add_test(c_api "/Users/neto/Desktop/EPX/EPX-CORE/build/tests/test_c_api")
set_tests_properties(c_api PROPERTIES  ENVIRONMENT "HOME=/tmp/epx-ctest/c_api;XDG_RUNTIME_DIR=/tmp/epx-ctest/c_api/run" TIMEOUT "30" _BACKTRACE_TRIPLES "/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;49;add_test;/Users/neto/Desktop/EPX/EPX-CORE/tests/CMakeLists.txt;0;")
