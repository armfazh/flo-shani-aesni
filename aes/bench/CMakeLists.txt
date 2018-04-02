cmake_minimum_required(VERSION 3.0.2)

include_directories(../..)
include_directories(../include)
add_executable(bench_aes
	clocks.h
	clocks.c
	bench.c
)
add_dependencies(bench_aes aesni_aes cpuid prng)
target_link_libraries(bench_aes aesni_aes cpuid prng crypto)
