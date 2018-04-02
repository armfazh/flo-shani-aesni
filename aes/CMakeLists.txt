project(aesni C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3 -std=c99 -maes -march=native -mtune=native")
set(LIBRARY_OUTPUT_PATH .)
include_directories(./include)
add_library(aesni_aes STATIC
		include/aesni.h
		src/aesni.c
		)

add_subdirectory(bench)
add_subdirectory(tests)