cmake_minimum_required(VERSION 3.9)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3 -pedantic -mavx2 -msha")

include_directories(./include)
add_library(shani src/coreshani.c src/shani.c include/shani.h src/libcrypto.a)

add_subdirectory(bench)
add_subdirectory(tests)
