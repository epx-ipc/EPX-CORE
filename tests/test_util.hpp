// Minimal test-checking helper shared by the tests/ programs. Deliberately
// not a third-party framework: EPX's only dependency is libsodium (see
// README.md), and pulling in a test framework for a handful of checks
// would break that. Each test_*.cpp is a small standalone program that
// exits non-zero (and CTest reports FAILED) if any CHECK() fails.
#pragma once

#include <cstdio>
#include <cstdlib>
#include <string>

inline int& epx_test_failures() {
    static int n = 0;
    return n;
}

#define CHECK(cond)                                                                    \
    do {                                                                                \
        if (!(cond)) {                                                                  \
            std::fprintf(stderr, "CHECK FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            epx_test_failures()++;                                                      \
        }                                                                               \
    } while (0)

#define CHECK_EQ(a, b)                                                                                 \
    do {                                                                                               \
        auto _a = (a); auto _b = (b);                                                                  \
        if (!(_a == _b)) {                                                                             \
            std::fprintf(stderr, "CHECK_EQ FAILED at %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b);  \
            epx_test_failures()++;                                                                     \
        }                                                                                               \
    } while (0)

#define TEST_MAIN_EXIT()                                                                \
    do {                                                                                \
        if (epx_test_failures() > 0) {                                                  \
            std::fprintf(stderr, "\n%d check(s) FAILED\n", epx_test_failures());        \
            return 1;                                                                  \
        }                                                                               \
        std::printf("all checks passed\n");                                            \
        return 0;                                                                       \
    } while (0)
