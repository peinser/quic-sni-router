cmake_minimum_required(VERSION 3.25)

project(quic-sni-router VERSION 0.1.0 LANGUAGES C)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBYAML REQUIRED IMPORTED_TARGET yaml-0.1)

option(QSR_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(QSR_BUILD_FUZZERS "Build libFuzzer targets" OFF)
option(QSR_BUILD_BENCHMARKS "Build local benchmark harnesses" OFF)
option(QSR_ENABLE_LTO "Enable interprocedural optimization for Release builds" OFF)
set(QSR_CPU_TARGET "" CACHE STRING "Release CPU target for Clang/GCC, for example native, znver3, or znver4")

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

function(qsr_apply_release_optimizations target_name)
  if(QSR_CPU_TARGET AND CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(${target_name} PRIVATE $<$<CONFIG:Release>:-march=${QSR_CPU_TARGET}>)
  endif()
endfunction()

if(QSR_ENABLE_LTO AND NOT QSR_ENABLE_SANITIZERS)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT QSR_IPO_SUPPORTED OUTPUT QSR_IPO_ERROR LANGUAGES C)
  if(QSR_IPO_SUPPORTED)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
  else()
    message(WARNING "QSR_ENABLE_LTO requested, but IPO/LTO is unsupported: ${QSR_IPO_ERROR}")
  endif()
endif()

add_library(qsr_core
  src/config.c
  src/metrics.c
  src/quic_crypto.c
  src/quic_frames.c
  src/quic_initial.c
  src/route_table.c
  src/runtime.c
  src/session_table.c
  src/tls_client_hello.c
  src/udp.c
)

target_include_directories(qsr_core PUBLIC include)
target_link_libraries(qsr_core PUBLIC OpenSSL::Crypto PkgConfig::LIBYAML)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(qsr_core PRIVATE _GNU_SOURCE)
endif()

target_compile_options(qsr_core PRIVATE
  -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror
)
qsr_apply_release_optimizations(qsr_core)

if(QSR_ENABLE_SANITIZERS)
  target_compile_options(qsr_core PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(qsr_core PUBLIC -fsanitize=address,undefined)
endif()

add_executable(quic-sni-router src/main.c)
target_link_libraries(quic-sni-router PRIVATE qsr_core)
target_compile_options(quic-sni-router PRIVATE
  -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror
)
qsr_apply_release_optimizations(quic-sni-router)

enable_testing()

add_executable(qsr_unit_tests
  tests/unit/test_config.c
  tests/unit/test_quic_crypto.c
  tests/unit/test_quic_frames.c
  tests/unit/test_quic_initial.c
  tests/unit/test_route_table.c
  tests/unit/test_session_table.c
  tests/unit/test_tls_client_hello.c
)
target_link_libraries(qsr_unit_tests PRIVATE qsr_core)
target_compile_definitions(qsr_unit_tests PRIVATE _POSIX_C_SOURCE=200809L)
target_compile_options(qsr_unit_tests PRIVATE
  -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror
)
add_test(NAME unit COMMAND qsr_unit_tests)

if(QSR_BUILD_FUZZERS AND CMAKE_C_COMPILER_ID MATCHES "Clang")
  foreach(fuzzer fuzz_quic_initial fuzz_quic_frames fuzz_tls_client_hello)
    add_executable(${fuzzer} tests/fuzz/${fuzzer}.c)
    target_link_libraries(${fuzzer} PRIVATE qsr_core)
    target_compile_options(${fuzzer} PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(${fuzzer} PRIVATE -fsanitize=fuzzer,address,undefined)
  endforeach()
endif()

if(QSR_BUILD_BENCHMARKS)
  add_executable(bench_dataplane tests/bench/bench_dataplane.c)
  target_link_libraries(bench_dataplane PRIVATE qsr_core)
  target_compile_definitions(bench_dataplane PRIVATE _POSIX_C_SOURCE=200809L)
  target_compile_options(bench_dataplane PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror
  )
  qsr_apply_release_optimizations(bench_dataplane)
endif()
