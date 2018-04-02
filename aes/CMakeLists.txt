cmake_minimum_required(VERSION 3.0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3 -maes -mssse3 -msse4.1")

add_library(flo-aesni STATIC flo-aesni.h aesni.c)
