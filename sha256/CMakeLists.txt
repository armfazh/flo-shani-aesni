cmake_minimum_required(VERSION 3.0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3 -pedantic -mavx2 -msha")

add_library(flo-shani flo-shani.c sha256_vectorized.c flo-shani.h)

