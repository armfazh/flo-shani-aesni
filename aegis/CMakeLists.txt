project(aesni C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3 -std=c99 -maes -march=native -mtune=native")
set(LIBRARY_OUTPUT_PATH .)
include_directories(./include)
add_library(aegis STATIC
		include/aegis.h
		src/aegis_opt.c
		src/aegis_ref.c
		)

add_subdirectory(bench)
add_subdirectory(tests)