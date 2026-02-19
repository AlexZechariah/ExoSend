# Phase 6: Unit Tests Configuration
# ExoSend Testing Framework

cmake_minimum_required(VERSION 3.20)

# Find Google Test
find_package(GTest REQUIRED)

# Include Google Test module
include(GoogleTest)

# ============================================================================
# Test Executable: protocol_test
# Tests ExoHeader serialization/deserialization
# ============================================================================
add_executable(protocol_test
    protocol_test.cpp
)

target_link_libraries(protocol_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(protocol_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(protocol_test)

# ============================================================================
# Test Executable: hash_test
# Tests SHA-256 hashing functionality
# ============================================================================
add_executable(hash_test
    hash_test.cpp
)

target_link_libraries(hash_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(hash_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(hash_test)

# ============================================================================
# Test Executable: json_test
# Tests discovery beacon JSON parsing
# ============================================================================
add_executable(json_test
    json_test.cpp
)

target_link_libraries(json_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(json_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(json_test)

# ============================================================================
# Test Executable: integration_test
# Tests multi-NIC discovery, peer GC, file transfer, settings persistence
# ============================================================================
add_executable(integration_test
    integration_test.cpp
)

target_link_libraries(integration_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
    iphlpapi
)

target_include_directories(integration_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(integration_test)

# ============================================================================
# Benchmark Tool: benchmark_tool
# Performance benchmarking for file transfer operations
# ============================================================================
add_executable(benchmark_tool
    benchmark_tool.cpp
)

target_link_libraries(benchmark_tool
    PRIVATE
    exosend-core
)

target_include_directories(benchmark_tool
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

# ============================================================================
# Test Executable: fault_injection_test
# Tests error handling and fault injection scenarios
# ============================================================================
add_executable(fault_injection_test
    fault_injection_test.cpp
)

target_link_libraries(fault_injection_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(fault_injection_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(fault_injection_test)

# ============================================================================
# Test Summary
# ============================================================================
message(STATUS "")
message(STATUS "==================================================")
message(STATUS "ExoSend Unit Tests Configured")
message(STATUS "==================================================")
message(STATUS "  protocol_test        - ExoHeader serialization tests")
message(STATUS "  hash_test            - SHA-256 hashing tests")
message(STATUS "  json_test            - Discovery beacon JSON tests")
message(STATUS "  integration_test     - Multi-NIC, GC, file transfer tests")
message(STATUS "  fault_injection_test - Error handling and fault injection")
message(STATUS "  benchmark_tool       - Performance benchmarking tool")
message(STATUS "==================================================")
message(STATUS "")
message(STATUS "Run tests with:")
message(STATUS "  ctest --test-dir ${CMAKE_BINARY_DIR} --config Release --verbose")
message(STATUS "")
message(STATUS "Or run individual tests:")
message(STATUS "  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/protocol_test")
message(STATUS "  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/hash_test")
message(STATUS "  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/json_test")
message(STATUS "  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/integration_test")
message(STATUS "  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/fault_injection_test")
message(STATUS "")
message(STATUS "Run benchmark tool:")
message(STATUS "  ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/benchmark_tool")
message(STATUS "==================================================")
message(STATUS "")
