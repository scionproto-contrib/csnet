# The benchmarks use Google Benchmark, which is written in C++.
enable_language(CXX)
set(CMAKE_CXX_STANDARD 17)

if (NOT CMAKE_BUILD_TYPE STREQUAL "Release")
    message(WARNING "The benchmarks measure the build type ${CMAKE_BUILD_TYPE}, use Release for meaningful results")
endif ()

set(DEPENDENCY_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/dependencies)

# Fetch Google Benchmark (https://github.com/google/benchmark), a library for microbenchmarks.
ExternalProject_Add(
        google_benchmark
        GIT_REPOSITORY https://github.com/google/benchmark.git
        GIT_TAG v1.9.1
        GIT_SHALLOW TRUE
        UPDATE_DISCONNECTED TRUE
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${DEPENDENCY_INSTALL_DIR} -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_BUILD_TYPE=Release -DBENCHMARK_ENABLE_TESTING=OFF -DBENCHMARK_INSTALL_DOCS=OFF ${DEPENDENCY_LAUNCHER_ARGS}
        BUILD_BYPRODUCTS ${DEPENDENCY_INSTALL_DIR}/lib/libbenchmark.a ${DEPENDENCY_INSTALL_DIR}/lib/libbenchmark_main.a
)

add_executable(benchmarks
        bench_socket.cc
)
add_dependencies(benchmarks google_benchmark)

target_compile_definitions(benchmarks PRIVATE BENCH_TOPOLOGY="${CMAKE_CURRENT_SOURCE_DIR}/topology.json")

# Give the benchmarks access to the internal headers and to the headers of Google Benchmark
target_include_directories(benchmarks PRIVATE ${PROJECT_SOURCE_DIR}/lib ${DEPENDENCY_INSTALL_DIR}/include)

find_package(Threads REQUIRED)
target_link_libraries(benchmarks PRIVATE scion ${DEPENDENCY_INSTALL_DIR}/lib/libbenchmark_main.a
        ${DEPENDENCY_INSTALL_DIR}/lib/libbenchmark.a Threads::Threads)

add_test(NAME benchmarks COMMAND benchmarks)
set_tests_properties(benchmarks PROPERTIES LABELS "benchmark")
