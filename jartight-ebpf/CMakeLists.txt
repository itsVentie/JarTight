cmake_minimum_required(VERSION 3.20)
project(JarTightEbpf C)

set(CMAKE_C_STANDARD 11)

add_library(jartight_ebpf OBJECT jartight.bpf.c)

target_compile_options(jartight_ebpf PRIVATE
    -target bpf
    -g
    -O2
    -Wall
)