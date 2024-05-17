#cmake_minimum_required(VERSION 3.24)
#project(av_detect)
#
#set(CMAKE_CXX_STANDARD 17)
#
#add_executable(av_detect main.cpp)
#
#set(CMAKE_EXE_LINKER_FLAGS "-static")

cmake_minimum_required(VERSION 3.24)
project(av_detect)

set(CMAKE_CXX_STANDARD 17)

# Añadir ruta a los archivos de cabecera
#include_directories(${CMAKE_SOURCE_DIR}/include)

# Añadir opciones de compilación
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Configuración para diferentes tipos de compilación
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Configuración para builds de depuración y producción
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3")

# Añadir el ejecutable
add_executable(av_detect main.cpp)

# Enlace estático
set(CMAKE_EXE_LINKER_FLAGS "-static")

