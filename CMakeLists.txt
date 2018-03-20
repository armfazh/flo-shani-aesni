cmake_minimum_required(VERSION 3.9)
project(flo_shani C)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH  ${CMAKE_BINARY_DIR}/lib )
#library
add_subdirectory(sha256)

#Auxiliary code
add_subdirectory(cpuid)
add_subdirectory(prng)

#Third-party code
