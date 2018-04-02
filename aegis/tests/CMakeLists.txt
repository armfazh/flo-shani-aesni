cmake_minimum_required(VERSION 2.8.4)
enable_language(CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3 -pedantic")
include_directories(../..)

# Locate GTest
find_package(GTest REQUIRED)
link_directories(${GTEST_LIBRARY_DIRS})

if(GTest_FOUND)
	include_directories(${GTEST_INCLUDE_DIRS})
	add_executable(tests_aegis runTests.cpp test_aegis.cpp)
	add_dependencies(tests_aegis aegis prng)
	target_link_libraries(tests_aegis ${GTEST_LIBRARIES} crypto aegis prng)
endif()
