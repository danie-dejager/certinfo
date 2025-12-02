cmake_minimum_required(VERSION 3.16)
project(certinfo VERSION 1.2.0 LANGUAGES C CXX)

# Options
option(BUILD_C "Build C implementation" ON)
option(BUILD_CPP "Build C++ implementation" ON)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Warnings
if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -pedantic)
endif()

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -pedantic)
endif()

# Sanitizers (Debug only)
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-fsanitize=address -fsanitize=undefined)
        add_link_options(-fsanitize=address -fsanitize=undefined)
    endif()
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# ---------------------------
# Generate version.h
# ---------------------------
configure_file(
    ${CMAKE_SOURCE_DIR}/src/version.h.in
    ${CMAKE_BINARY_DIR}/generated/version.h
    @ONLY
)

include_directories(${CMAKE_BINARY_DIR}/generated)

# C implementation
if (BUILD_C)
    add_executable(certinfo_c src/c/certinfo.c)
    target_link_libraries(certinfo_c PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    install(TARGETS certinfo_c)
endif()

# C++ implementation
if (BUILD_CPP)
    add_executable(certinfo_cpp src/cpp/certinfo.cpp)
    target_link_libraries(certinfo_cpp PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    install(TARGETS certinfo_cpp)
endif()

message(STATUS "Build C:   ${BUILD_C}")
message(STATUS "Build C++: ${BUILD_CPP}")
message(STATUS "Project version: ${PROJECT_VERSION}")
