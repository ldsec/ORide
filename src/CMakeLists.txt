CMAKE_MINIMUM_REQUIRED(VERSION 2.8.1)

PROJECT(oride)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Ofast -Wall")

option(PLAINTEXT_20_BITS "Use a plaintext space of 20 bits instead of 30 for uint32_t" OFF)
if(PLAINTEXT_20_BITS)
    message(STATUS "Using 20-bit plaintexts for uint32_t")
    add_definitions(-DPLAINTEXT_20_BITS)
else()
    message(STATUS "Using 30-bit plaintexts for uint32_t")
endif()

OPTION(NFL_OPTIMIZED "Build an optimized version of NFL" OFF)
IF(NFL_OPTIMIZED)
    MESSAGE(STATUS "Tring to use optimized version of NFL")
    ADD_DEFINITIONS(-DNFL_OPTIMIZED)

    INCLUDE(CheckCXXSourceCompiles)
    SET(CMAKE_CXX_FLAGS_OLD ${CMAKE_CXX_FLAGS})
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")

    CHECK_CXX_SOURCE_COMPILES("#include <immintrin.h>\nint main() { return 0;}" NFLLIB_USE_AVX)
    CHECK_CXX_SOURCE_COMPILES("#include <pmmintrin.h>\nint main() { return 0;}" NFLLIB_USE_SSE)
    IF(NFLLIB_USE_AVX)
        MESSAGE(STATUS "Using AVX vector engine")
        ADD_DEFINITIONS(-DNTT_AVX)
    ELSEIF(NFLLIB_USE_SSE)
        MESSAGE(STATUS "Using SSE vector engine")
        ADD_DEFINITIONS(-DNTT_SSE)
    ELSE()
        MESSAGE(ERROR "Asking for optimized mode but neither SSE not AVX support detected")
    ENDIF()
ENDIF()

ADD_DEFINITIONS(-DNOISE_ESTIMATE)


SET(nfl_path ../NFLlib)

INCLUDE_DIRECTORIES(
    ${nfl_path}/include/
)

LINK_DIRECTORIES(
    ${nfl_path}/_build/
)


ADD_EXECUTABLE(
    test_simple
    stats.cpp
    util.cpp
    test_simple.cpp
)

TARGET_LINK_LIBRARIES(test_simple nfllib_static mpfr gmpxx gmp)

