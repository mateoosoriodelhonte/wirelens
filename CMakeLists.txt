cmake_minimum_required(VERSION 3.28)

project(
  WireLens
  VERSION 0.1.0
  DESCRIPTION "Local-first visual network protocol inspector"
  LANGUAGES CXX)

option(WIRELENS_BUILD_TESTS "Build WireLens tests" ON)
option(WIRELENS_WARNINGS_AS_ERRORS "Treat WireLens compiler warnings as errors" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(cmake/Dependencies.cmake)

if(WIRELENS_BUILD_TESTS)
  include(CTest)
  enable_testing()
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/core/CMakeLists.txt")
  add_subdirectory(core)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cli/CMakeLists.txt")
  add_subdirectory(cli)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/wasm/CMakeLists.txt")
  add_subdirectory(wasm)
endif()
