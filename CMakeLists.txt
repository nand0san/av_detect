cmake_minimum_required(VERSION 3.24)
project(av_detect)

set(CMAKE_CXX_STANDARD 17)

# Version (fuente unica de verdad)
set(VERSION_MAJOR 2)
set(VERSION_MINOR 3)
set(VERSION_PATCH 0)

# Pasar version a compilador C++ y RC
add_definitions(
    -DVERSION_MAJOR=${VERSION_MAJOR}
    -DVERSION_MINOR=${VERSION_MINOR}
    -DVERSION_PATCH=${VERSION_PATCH}
)

# Opciones de compilacion
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Strip en Release (elimina secciones DWARF que disparan heuristicas AV)
set(CMAKE_CXX_FLAGS_RELEASE "-O2")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-s")

# Directorio de salida
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Ejecutable con recurso de version
enable_language(RC)
add_executable(av_detect main.cpp version.rc)
