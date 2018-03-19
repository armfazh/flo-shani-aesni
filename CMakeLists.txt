cmake_minimum_required(VERSION 3.9)
project(flo_shani C)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH  ${CMAKE_BINARY_DIR}/lib )
#library
add_subdirectory(sha256)

#third-party code
add_subdirectory(prng)
