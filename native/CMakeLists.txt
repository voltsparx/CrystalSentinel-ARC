cmake_minimum_required(VERSION 3.24)

project(sentinel_native LANGUAGES C CXX)

include(CTest)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(SENTINEL_ENABLE_ASM "Enable assembly fast-path primitives" OFF)

add_library(
  sentinel-native-c STATIC
  c/src/resource_guard.c
  c/src/budget_guard.c
  c/src/exposure_guard.c
  c/src/protocol_budget.c
  c/src/mesh_guard.c
  c/src/dynamic_load_balancer.c
  c/src/heartbeat_audit.c
  c/src/guardian_handoff.c
)
target_include_directories(sentinel-native-c PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(
  sentinel-native-cpp STATIC
  cpp/src/classifier.cpp
  cpp/src/scan_predictor.cpp
  cpp/src/ambient_state.cpp
  cpp/src/behavior_matrix.cpp
  cpp/src/recovery_predictor.cpp
  cpp/src/guardian_reporter.cpp
  cpp/src/mesh_gossip.cpp
)
target_include_directories(sentinel-native-cpp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(SENTINEL_ENABLE_ASM)
  enable_language(ASM_NASM)
  add_library(
    sentinel-native-asm STATIC
    asm/src/fastpath.asm
    asm/src/pressure_mix.asm
    asm/src/directive.asm
  )
endif()

if(BUILD_TESTING)
  add_executable(
    sentinel-native-smoke
    tests/native_smoke.cpp
  )
  target_include_directories(
    sentinel-native-smoke
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
  )
  target_link_libraries(
    sentinel-native-smoke
    PRIVATE
    sentinel-native-c
    sentinel-native-cpp
  )

  if(SENTINEL_ENABLE_ASM)
    target_link_libraries(sentinel-native-smoke PRIVATE sentinel-native-asm)
    target_compile_definitions(sentinel-native-smoke PRIVATE SENTINEL_NATIVE_HAS_ASM=1)
  endif()

  add_test(NAME sentinel-native-smoke COMMAND sentinel-native-smoke)
endif()
