cmake_minimum_required(VERSION 3.24)

project(sentinel_native LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(SENTINEL_ENABLE_ASM "Enable assembly fast-path primitives" OFF)

add_library(sentinel-native-c STATIC c/src/resource_guard.c c/src/budget_guard.c)
target_include_directories(sentinel-native-c PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(sentinel-native-cpp STATIC cpp/src/classifier.cpp cpp/src/scan_predictor.cpp)
target_include_directories(sentinel-native-cpp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(SENTINEL_ENABLE_ASM)
  enable_language(ASM_NASM)
  add_library(sentinel-native-asm STATIC asm/src/fastpath.asm)
endif()
