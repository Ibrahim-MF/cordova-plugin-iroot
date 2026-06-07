cmake_minimum_required(VERSION 3.18.1)
project(native_probe)

add_library(native_probe SHARED native_probe.c)

find_library(log-lib log)
target_link_libraries(native_probe ${log-lib})
