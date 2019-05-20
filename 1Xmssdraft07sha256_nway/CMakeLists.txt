
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -mavx2 -O3 -lm -std=c99 -march=native -mtune=native")

add_library(flo-xmss-seq-1x STATIC flo-xmss-vec.h xmss.c)
add_library(flo-xmss-vec-4x STATIC flo-xmss-vec.h xmss.c)
add_library(flo-xmss-vec-8x STATIC flo-xmss-vec.h xmss.c)

target_compile_definitions(flo-xmss-seq-1x PRIVATE "-DXMSS_SHA2_1x")
target_compile_definitions(flo-xmss-vec-4x PRIVATE "-DXMSS_SHA2_4x")
target_compile_definitions(flo-xmss-vec-8x PRIVATE "-DXMSS_SHA2_8x")
