cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

# Application versino
set(PROJECT_NAME FPQPacker)
project(${PROJECT_NAME} VERSION "0.4")
configure_file(src/app/version.h.in version.h)

# Set compiler && linker options
set(CMAKE_CXX_STANDARD 11)
add_compile_options(-c -fmessage-length=0 -Wall -Wcomment -Os -s)
add_link_options(-s)
if (DEFINED CMAKE_TOOLCHAIN_FILE)
    message("-- ${PROJECT_NAME} using toolchain: ${CMAKE_TOOLCHAIN_FILE}")
    if(CMAKE_SYSTEM_NAME MATCHES "Windows")
        set(CMAKE_CXX_STANDARD_LIBRARIES "-static-libgcc -static-libstdc++ ${CMAKE_CXX_STANDARD_LIBRARIES}")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-Bstatic,--whole-archive -Wl,--no-whole-archive")
        set(SRC src/app/fpq_pack src/_windows/getopt)
    else()
        message(FATAL_ERROR "Unknown CMake system name!")
    endif()
else()
    set(SRC src/app/fpq_pack)
endif()

add_subdirectory(src/crc32)

# Build application
set(NAME fpq_pack)
add_executable(${NAME} ${SRC})
target_include_directories(${NAME} PUBLIC build/)
target_include_directories(${NAME} PUBLIC src/crc32/)
target_link_libraries(${NAME} PUBLIC crc32)
