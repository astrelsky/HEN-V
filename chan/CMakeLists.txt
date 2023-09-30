###################################################################################################
# PS5SDK - CRT build script
# @author Znullptr
###################################################################################################

cmake_minimum_required (VERSION 3.20)

set(basename "chan")
project(${basename} C)

# Language Standard Defaults
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

if ("${CMAKE_C_COMPILER_ID}" MATCHES "[Cc]lang")
	set(IS_CLANG 1)
else()
	message(FATAL_ERROR "${PROJECT_NAME} is meant to be built with clang! CompilerID: ${CMAKE_C_COMPILER_ID}")
endif()

if (NOT DEFINED D_PS5SDK)
	set(D_PS5SDK ".")
endif()

########## finalize main target sources ##########

file(GLOB SrcFiles src/*.c)

add_library(${PROJECT_NAME} STATIC ${SrcFiles})
target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
