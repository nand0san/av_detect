cmake_minimum_required(VERSION 3.24)
project(av_detect)

set(CMAKE_CXX_STANDARD 17)

add_executable(av_detect main.cpp)

set(CMAKE_EXE_LINKER_FLAGS "-static")
