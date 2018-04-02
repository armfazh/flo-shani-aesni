cmake_minimum_required(VERSION 3.0)
project(flo-shani-aesni C)

set(CMAKE_C_STANDARD 99)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH  ${CMAKE_BINARY_DIR}/lib )

#point to the instalation directory of OpenSSL version 1.0.2
include_directories(/opt/ossl102/include)
link_directories(/opt/ossl102/lib)

# our library
add_subdirectory(sha256)
add_subdirectory(aes)
add_subdirectory(aegis)

# auxiliary libraries
add_subdirectory(cpuid)
add_subdirectory(prng)

# Applications
add_subdirectory(bench)
add_subdirectory(tests)
