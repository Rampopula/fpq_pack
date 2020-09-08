cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# Application versino
set(PROJECT_NAME FPQPack)
project(${PROJECT_NAME} VERSION "1.0.0")

# Compiler
add_compile_options(-c -fmessage-length=0 -Wall -Wcomment)
set(CMAKE_CXX_STANDARD 11)

# Libraries

# Build application
set(NAME fpq_pack)
set(SRC fpq_pack)
add_executable(${NAME} ${SRC})
