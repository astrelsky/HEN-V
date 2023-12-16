cmake_minimum_required (VERSION 3.20)

project("henv")

set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_ROOT}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_ROOT}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_ROOT}/lib)	# static libs are archive

include_directories	(SYSTEM "${PROJECT_ROOT}/include")
include_directories(SYSTEM "${D_PS5SDK}")
include_directories(SYSTEM "${D_PS5SDK}/include")

add_subdirectory(chan)
#add_subdirectory(spawner)

# this was too complicated
#include(FetchContent)
#FetchContent_Declare(
#  NidResolver
#  GIT_REPOSITORY https://github.com/astrelsky/libNidResolver.git
#  OVERRIDE_FIND_PACKAGE
#)
#FetchContent_MakeAvailable(NidResolver)

add_subdirectory(libNidResolver)
add_subdirectory(shared)
#add_subdirectory(daemon)
add_subdirectory(spawner)
