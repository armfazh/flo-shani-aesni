cmake_minimum_required(VERSION 3.9)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3 -pedantic -mavx2 -msha -mavx512f -mavx512bw")

include_directories(./include)
add_library(shani src/shani.c src/sha256_vectorized.c include/shani.h)

add_subdirectory(bench)
add_subdirectory(tests)
