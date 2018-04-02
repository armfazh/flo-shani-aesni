cmake_minimum_required(VERSION 3.0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3 -maes")

add_library(flo-aegis STATIC flo-aegis.h aegis_opt.c aegis_ref.c)
