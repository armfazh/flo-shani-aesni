cmake_minimum_required(VERSION 3.9)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3 -pedantic -mavx2 -msha")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} " )

include_directories(./include)
add_library(shani src/coreshani.c src/shani.c include/shani.h)

add_subdirectory(bench)
add_subdirectory(tests)
