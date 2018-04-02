cmake_minimum_required(VERSION 3.0)
enable_language(CXX)

include_directories(../sha256)
include_directories(../prng)
include_directories(../cpuid)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3 -pedantic -mavx2 -msha")

# Locate GTest
find_package(GTest REQUIRED)
link_directories(${GTEST_LIBRARY_DIRS})

if(GTest_FOUND)
	include_directories(${GTEST_INCLUDE_DIRS})
	add_executable(tests_sha256 runTests.cpp test_shani.cpp )
	add_dependencies(tests_sha256 flo-shani flo-prng)
	target_link_libraries(tests_sha256 ${GTEST_LIBRARIES} crypto flo-shani flo-prng)
endif()
