cmake_minimum_required(VERSION 3.0)

include_directories(../sha256)
include_directories(../aes)
include_directories(../aegis)
include_directories(../prng)
include_directories(../cpuid)

add_executable       (bench_sha256 bench_sha256.c clocks.h )
add_dependencies     (bench_sha256 flo-shani flo-cpuid flo-prng)
target_link_libraries(bench_sha256 flo-shani flo-cpuid flo-prng crypto)

add_executable       (bench_aes bench_aes.c clocks.h )
add_dependencies     (bench_aes flo-aesni flo-cpuid flo-prng)
target_link_libraries(bench_aes flo-aesni flo-cpuid flo-prng crypto)

add_executable       (bench_aegis bench_aegis.c clocks.h )
add_dependencies     (bench_aegis flo-aegis flo-cpuid flo-prng)
target_link_libraries(bench_aegis flo-aegis flo-cpuid flo-prng crypto)
