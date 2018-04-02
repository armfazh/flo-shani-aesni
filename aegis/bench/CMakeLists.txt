cmake_minimum_required(VERSION 3.0.2)

include_directories(../..)
include_directories(../include)
add_executable(bench_aegis
	clocks.h
	clocks.c
	bench.c
)
add_dependencies(bench_aegis aegis cpuid prng)
target_link_libraries(bench_aegis aegis cpuid prng crypto)
