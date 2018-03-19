cmake_minimum_required(VERSION 2.8.4)
enable_language(CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3 -pedantic -mavx2 -msha")
include_directories(../..)

# Locate GTest
find_package(GTest REQUIRED)
link_directories(${GTEST_LIBRARY_DIRS})

if(GTest_FOUND)
	include_directories(${GTEST_INCLUDE_DIRS})
	add_executable(tests_sha256 runTests.cpp test_shani.cpp )
	add_dependencies(tests_sha256 shani prng)
	target_link_libraries(tests_sha256 ${GTEST_LIBRARIES} crypto shani prng)
endif()
