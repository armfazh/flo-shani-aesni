# The MIT License (MIT)
# Copyright (c) 2018 Armando Faz
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
# OR OTHER DEALINGS IN THE SOFTWARE.
cmake_minimum_required(VERSION 3.0)

include_directories(../sha256)
include_directories(../aes)
include_directories(../aegis)
include_directories(../1Xmssdraft07sha256_nway)
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

add_executable(bench_xmss_seq_1x bench_xmss_vec.c clocks.c clocks.h)
add_executable(bench_xmss_vec_4x bench_xmss_vec.c clocks.c clocks.h)
add_executable(bench_xmss_vec_8x bench_xmss_vec.c clocks.c clocks.h)

target_compile_definitions(bench_xmss_seq_1x PRIVATE "-DXMSS_SHA2_1x")
target_compile_definitions(bench_xmss_vec_4x PRIVATE "-DXMSS_SHA2_4x")
target_compile_definitions(bench_xmss_vec_8x PRIVATE "-DXMSS_SHA2_8x")
target_link_libraries(bench_xmss_seq_1x flo-xmss-seq-1x flo-cpuid flo-prng crypto m)
target_link_libraries(bench_xmss_vec_4x flo-xmss-vec-4x flo-cpuid flo-prng crypto m)
target_link_libraries(bench_xmss_vec_8x flo-xmss-vec-8x flo-cpuid flo-prng crypto m)
