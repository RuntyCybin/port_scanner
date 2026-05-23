cmake_minimum_required(VERSION 3.16)
project(port_scanner VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(port_scanner
    src/main.cpp
    src/scanner.cpp
)

target_include_directories(port_scanner PRIVATE src)

target_compile_options(port_scanner PRIVATE -O2 -Wall -Wextra)

find_package(Threads REQUIRED)
target_link_libraries(port_scanner PRIVATE Threads::Threads)
