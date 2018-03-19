cmake_minimum_required(VERSION 3.0.2)

include_directories(../..)
include_directories(../include)
add_executable(bench_sha256
	clocks.h
	clocks.c
	bench.c
)
add_dependencies(bench_sha256 shani prng)
target_link_libraries(bench_sha256	shani prng crypto)
