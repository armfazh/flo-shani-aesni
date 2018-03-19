/**
 * Copyright (c) 2017 Armando Faz <armfazh@ic.unicamp.br>.
 * Institute of Computing.
 * University of Campinas, Brazil.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, version 2 or greater.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef CLOCKS_H
#define CLOCKS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __INTEL_COMPILER
#define BARRIER __memory_barrier()
#else
#define BARRIER __asm__ __volatile__("" ::: "memory")
#endif

#define CLOCKS_RANDOM(RANDOM, FUNCTION)    \
  do {                                            \
    uint64_t t_start, t_end;                      \
    int64_t i_bench, j_bench;                     \
    unsigned cycles_high0, cycles_low0;           \
    unsigned cycles_high1, cycles_low1;           \
    __asm__ __volatile__(                         \
        "mfence \n\t"                             \
        "RDTSC \n\t"                              \
        "mov %%edx, %0\n\t"                       \
        "mov %%eax, %1\n\t"                       \
        : "=r"(cycles_high0), "=r"(cycles_low0)   \
        ::"%rax", "%rbx", "%rcx","%rdx");         \
    BARRIER;                                      \
    i_bench = BENCH_TIMES;                        \
    do {                                          \
      j_bench = BENCH_TIMES;                      \
      RANDOM;                                     \
      do {                                        \
        FUNCTION;                                 \
        j_bench--;                                \
      } while (j_bench != 0);                     \
      i_bench--;                                  \
    } while (i_bench != 0);                       \
    BARRIER;                                      \
    __asm__ __volatile__(                         \
        "mfence \n\t"                             \
        "RDTSCP \n\t"                             \
        "mov %%edx, %0\n\t"                       \
        "mov %%eax, %1\n\t"                       \
        : "=r"(cycles_high1), "=r"(cycles_low1)   \
        ::"%rax", "%rbx", "%rcx", "%rdx");        \
    t_start = (((uint64_t)cycles_high0) << 32) | cycles_low0; \
    t_end   = (((uint64_t)cycles_high1) << 32) | cycles_low1; \
    CYCLES = (t_end - t_start) / (BENCH_TIMES * BENCH_TIMES); \
  } while (0)

#define CLOCKS(FUNCTION) CLOCKS_RANDOM(while (0), FUNCTION)

#define oper_second(RANDOM, LABEL, FUNCTION)                 \
  do {                                                       \
    printf("%-8s: ", LABEL);                                 \
    RANDOM;                                                  \
                                                             \
    unsigned i;                                              \
    uint64_t start, end;                                     \
    const unsigned iterations = 100000;                      \
    uint64_t start_c, end_c;                                 \
                                                             \
    /* Load the caches*/                                     \
    for (i = 0; i < 1000; ++i) {                             \
      FUNCTION;                                              \
    }                                                        \
                                                             \
    start = time_now();                                      \
    start_c = cycles_now();                                  \
    for (i = 0; i < iterations; ++i) {                       \
      FUNCTION;                                              \
    }                                                        \
    end = time_now();                                        \
    end_c = cycles_now();                                    \
                                                             \
    printf("%3lu µs, %8.1f oper/s, %6lu cycles/op\n",        \
           (uint64_t)((end - start) / iterations),      \
           iterations*(double)1e6 / (end - start),           \
           (uint64_t)((end_c - start_c) / iterations)); \
  } while (0)

uint64_t time_now();
uint64_t cycles_now(void);

#endif /* CLOCKS_H */
