###################################################################################################
# PS5SDK - Example: pipe pirate
# Uses the read/write primitive to read and write some kernel data.
# @authors ChendoChap, Specter, Znullptr
###################################################################################################

cmake_minimum_required (VERSION 3.20)

set(basename "HenVShared")
project(${basename} C)

# Language Standard Defaults
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Check for sub-project as part of main build or external build
if (NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
	set(IS_SUBPROJECT TRUE)
else()
	set(IS_SUBPROJECT FALSE)
endif()

message("IS_SUBPROJECT: ${IS_SUBPROJECT}")

set(D_CWD "${PROJECT_SOURCE_DIR}")


# Headers
include_directories	(SYSTEM "${D_PS5SDK}")
include_directories	(SYSTEM "${D_PS5SDK}/include")

set(D_SRC ${D_CWD}/source)

file(GLOB SrcFiles ${D_SRC}/*.c ${D_SRC}/*.h)

add_library(${PROJECT_NAME} STATIC ${SrcFiles})
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "${PROJECT_NAME}")

# Finalize main target sources
target_compile_options(${PROJECT_NAME} PUBLIC
	$<$<COMPILE_LANGUAGE:C>:${C_DEFS} ${C_FLAGS}>
)

message("========== build: ${PROJECT_NAME} ==========")

set(CMAKE_C_FLAGS "--target=x86_64-freebsd-pc-elf -march=znver2 -gfull -gdwarf-2 -O0")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c17 -Wall -Wextra -Werror -pedantic-errors")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPPR -DPS5 -DPS5_FW_VERSION=${V_FW}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112 -D__BSD_VISIBLE=1 -D__XSI_VISIBLE=500")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-builtin -nostdlib")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -fPIE")
target_include_directories(${PROJECT_NAME} PRIVATE "${D_CWD}/include")
target_include_directories(${PROJECT_NAME} PRIVATE "${D_CWD}/../libNidResolver/include")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
