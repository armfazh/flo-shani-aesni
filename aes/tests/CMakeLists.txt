cmake_minimum_required(VERSION 2.8.4)
enable_language(CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3 -pedantic")
include_directories(../..)

# Locate GTest
find_package(GTest REQUIRED)
link_directories(${GTEST_LIBRARY_DIRS})

if(GTest_FOUND)
	include_directories(${GTEST_INCLUDE_DIRS})
	add_executable(tests_aes runTests.cpp test_aesni_aes.cpp)
	add_dependencies(tests_aes aesni_aes prng)
	target_link_libraries(tests_aes ${GTEST_LIBRARIES} crypto aesni_aes prng)
endif()
