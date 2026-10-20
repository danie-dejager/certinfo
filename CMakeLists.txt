cmake_minimum_required(VERSION 3.16)
project(certinfo VERSION 1.4.0 LANGUAGES C CXX)

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
    ${PROJECT_SOURCE_DIR}/src/version.h.in
    ${PROJECT_BINARY_DIR}/generated/version.h
    @ONLY
)


# C implementation
if (BUILD_C)
    add_executable(certinfo_c src/c/certinfo.c)
    target_include_directories(certinfo_c PRIVATE ${PROJECT_BINARY_DIR}/generated)
    target_link_libraries(certinfo_c PRIVATE OpenSSL::Crypto)
    install(TARGETS certinfo_c)
endif()

# C++ implementation
if (BUILD_CPP)
    add_executable(certinfo_cpp src/cpp/certinfo.cpp)
    target_include_directories(certinfo_cpp PRIVATE ${PROJECT_BINARY_DIR}/generated)
    target_link_libraries(certinfo_cpp PRIVATE OpenSSL::Crypto)
    install(TARGETS certinfo_cpp)
endif()

message(STATUS "Build C:   ${BUILD_C}")
message(STATUS "Build C++: ${BUILD_CPP}")
message(STATUS "Project version: ${PROJECT_VERSION}")

include(CTest)
if (BUILD_TESTING)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if (Python3_Interpreter_FOUND AND (BUILD_C OR BUILD_CPP))
        add_executable(certinfo_test_cert tests/create_certificate.c)
        target_link_libraries(certinfo_test_cert PRIVATE OpenSSL::Crypto)

        set(CERTINFO_TEST_IMPLEMENTATIONS)
        if (BUILD_C)
            list(APPEND CERTINFO_TEST_IMPLEMENTATIONS
                --implementation "C=$<TARGET_FILE:certinfo_c>")
        endif()
        if (BUILD_CPP)
            list(APPEND CERTINFO_TEST_IMPLEMENTATIONS
                --implementation "C++=$<TARGET_FILE:certinfo_cpp>")
        endif()

        execute_process(
            COMMAND ${Python3_EXECUTABLE} -c "import cryptography"
            RESULT_VARIABLE CERTINFO_PYTHON_CRYPTOGRAPHY_RESULT
            OUTPUT_QUIET
            ERROR_QUIET
        )
        set(CERTINFO_TEST_PYTHON_ARGUMENTS)
        if (CERTINFO_PYTHON_CRYPTOGRAPHY_RESULT EQUAL 0)
            list(APPEND CERTINFO_TEST_PYTHON_ARGUMENTS
                --python-script ${PROJECT_SOURCE_DIR}/src/certinfo.py)
        else()
            message(STATUS "Python conformance tests disabled: cryptography is not installed")
        endif()

        add_test(
            NAME certinfo_conformance
            COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/conformance.py
                --generator $<TARGET_FILE:certinfo_test_cert>
                --version ${PROJECT_VERSION}
                ${CERTINFO_TEST_IMPLEMENTATIONS}
                ${CERTINFO_TEST_PYTHON_ARGUMENTS}
        )
    elseif(NOT Python3_Interpreter_FOUND)
        message(STATUS "Certinfo tests disabled: Python 3 interpreter not found")
    endif()
endif()
