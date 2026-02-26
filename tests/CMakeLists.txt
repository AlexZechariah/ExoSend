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
# Test Executable: atomic_file_test
# Tests atomic write helpers (temp file then rename)
# ============================================================================
add_executable(atomic_file_test
    atomic_file_test.cpp
)

target_link_libraries(atomic_file_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(atomic_file_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(atomic_file_test)

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
# Test Executable: trust_store_test
# Tests pairing and pinning trust store persistence
# ============================================================================
add_executable(trust_store_test
    trust_store_test.cpp
)

target_link_libraries(trust_store_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(trust_store_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(trust_store_test)

# ============================================================================
# Test Executable: fingerprint_utils_test
# Tests fingerprint normalization/formatting for pairing and pinning
# ============================================================================
add_executable(fingerprint_utils_test
    fingerprint_utils_test.cpp
)

target_link_libraries(fingerprint_utils_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(fingerprint_utils_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(fingerprint_utils_test)

# ============================================================================
# Test Executable: queue_manager_test
# Tests TransferQueueManager concurrency accounting
# ============================================================================
add_executable(queue_manager_test
    queue_manager_test.cpp
)

target_link_libraries(queue_manager_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(queue_manager_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(queue_manager_test)

# ============================================================================
# Test Executable: incoming_transfer_policy_test
# Tests auto-accept decision policy (security hardening)
# ============================================================================
add_executable(incoming_transfer_policy_test
    incoming_transfer_policy_test.cpp
)

target_link_libraries(incoming_transfer_policy_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(incoming_transfer_policy_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(incoming_transfer_policy_test)

# ============================================================================
# Test Executable: tls_callback_test
# Tests TLS certificate verification callback behavior (v0.3.0 security fix)
# ============================================================================
add_executable(tls_callback_test
    tls_callback_test.cpp
)

target_link_libraries(tls_callback_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(tls_callback_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(tls_callback_test)

# ============================================================================
# Test Executable: tls_exporter_test
# Tests RFC 9266 tls-exporter channel binding helper
# ============================================================================
add_executable(tls_exporter_test
    tls_exporter_test.cpp
)

target_link_libraries(tls_exporter_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(tls_exporter_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(tls_exporter_test)

# ============================================================================
# Test Executable: pairing_secret_test
# Tests pairing secret generation and Base32 encoding/decoding helpers
# ============================================================================
add_executable(pairing_secret_test
    pairing_secret_test.cpp
)

target_link_libraries(pairing_secret_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(pairing_secret_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(pairing_secret_test)

# ============================================================================
# Test Executable: pairing_confirm_test
# Tests HKDF + HMAC pairing confirmation helpers
# ============================================================================
add_executable(pairing_confirm_test
    pairing_confirm_test.cpp
)

target_link_libraries(pairing_confirm_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(pairing_confirm_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(pairing_confirm_test)

# ============================================================================
# Test Executable: pairing_handshake_test
# Integration tests for PAIR_REQ/PAIR_RESP pairing handshake
# ============================================================================
add_executable(pairing_handshake_test
    pairing_handshake_test.cpp
)

target_link_libraries(pairing_handshake_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(pairing_handshake_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(pairing_handshake_test)

# ============================================================================
# Test Executable: transfer_server_dos_test
# Tests basic DoS hardening controls on TransferServer (thread caps)
# ============================================================================
add_executable(transfer_server_dos_test
    transfer_server_dos_test.cpp
)

target_link_libraries(transfer_server_dos_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(transfer_server_dos_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(transfer_server_dos_test)

# ============================================================================
# Test Executable: connection_rate_limiter_test
# Tests per-IP TCP connection rate limiting helper
# ============================================================================
add_executable(connection_rate_limiter_test
    connection_rate_limiter_test.cpp
)

target_link_libraries(connection_rate_limiter_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(connection_rate_limiter_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(connection_rate_limiter_test)

# ============================================================================
# Test Executable: trust_store_dpapi_test
# Tests DPAPI protect-or-preserve semantics for trust store persistence
# ============================================================================
add_executable(trust_store_dpapi_test
    trust_store_dpapi_test.cpp
)

target_link_libraries(trust_store_dpapi_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(trust_store_dpapi_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(trust_store_dpapi_test)

# ============================================================================
# Test Executable: protected_blob_test
# Tests DPAPI ProtectedBlob encrypt/decrypt round-trip (Windows only)
# ============================================================================
if(WIN32)
    add_executable(protected_blob_test
        protected_blob_test.cpp
    )

    target_link_libraries(protected_blob_test
        PRIVATE
        exosend-core
        GTest::gtest
        GTest::gtest_main
    )

    target_include_directories(protected_blob_test
        PRIVATE
        ${CMAKE_SOURCE_DIR}/include
    )

    gtest_discover_tests(protected_blob_test)
endif()

# ============================================================================
# Test Executable: windows_acl_test
# Tests Windows-only ACL hardening helper (v0.3)
# ============================================================================
if(WIN32)
    add_executable(windows_acl_test
        windows_acl_test.cpp
    )

    target_link_libraries(windows_acl_test
        PRIVATE
        exosend-core
        GTest::gtest
        GTest::gtest_main
    )

    target_include_directories(windows_acl_test
        PRIVATE
        ${CMAKE_SOURCE_DIR}/include
    )

    gtest_discover_tests(windows_acl_test)
endif()

# ============================================================================
# Test Executable: pairing_limiter_test
# Tests PairingPromptLimiter rate-limiting and cooldown behavior
# ============================================================================
add_executable(pairing_limiter_test
    pairing_limiter_test.cpp
)

target_link_libraries(pairing_limiter_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(pairing_limiter_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(pairing_limiter_test)

# ============================================================================
# Test Executable: beacon_rate_limiter_test
# Tests per-IP sliding-window rate limiter for discovery beacons (v0.3)
# ============================================================================
add_executable(beacon_rate_limiter_test
    beacon_rate_limiter_test.cpp
)

target_link_libraries(beacon_rate_limiter_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(beacon_rate_limiter_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(beacon_rate_limiter_test)

# ============================================================================
# Test Executable: beacon_security_test
# Tests goodbye IP validation, rate-limit flood, timestamp anti-replay (v0.3)
# ============================================================================
add_executable(beacon_security_test
    beacon_security_test.cpp
)

target_link_libraries(beacon_security_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(beacon_security_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(beacon_security_test)

# ============================================================================
# Test Executable: transfer_server_port_test
# Tests bind(0)+getsockname dynamic TCP port and IP validator callback (v0.3)
# ============================================================================
add_executable(transfer_server_port_test
    transfer_server_port_test.cpp
)

target_link_libraries(transfer_server_port_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
    ws2_32
)

target_include_directories(transfer_server_port_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(transfer_server_port_test)

# ============================================================================
# Test Executable: discovery_port_test
# Tests UDP pool binding, collision fallback, and beacon field validation (v0.3)
# ============================================================================
add_executable(discovery_port_test
    discovery_port_test.cpp
)

target_link_libraries(discovery_port_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
    ws2_32
)

target_include_directories(discovery_port_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(discovery_port_test)

# ============================================================================
# Test Executable: windows_filename_test
# Tests Windows filename sanitization hardening (ADS, reserved names, invalid chars)
# ============================================================================
add_executable(windows_filename_test
    windows_filename_test.cpp
)

target_link_libraries(windows_filename_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(windows_filename_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(windows_filename_test)

# ============================================================================
# Test Executable: file_receiver_filename_test
# Ensures receiver rejects dangerous offer filenames before any file I/O.
# ============================================================================
add_executable(file_receiver_filename_test
    file_receiver_filename_test.cpp
)

target_link_libraries(file_receiver_filename_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(file_receiver_filename_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(file_receiver_filename_test)

# ============================================================================
# Test Executable: app_paths_test
# Verifies canonical LocalAppData path contract and legacy path detection.
# ============================================================================
add_executable(app_paths_test
    app_paths_test.cpp
)

target_link_libraries(app_paths_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(app_paths_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(app_paths_test)

# ============================================================================
# Test Executable: migration_utils_test
# Tests best-effort on-disk migration helpers.
# ============================================================================
add_executable(migration_utils_test
    migration_utils_test.cpp
)

target_link_libraries(migration_utils_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(migration_utils_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(migration_utils_test)

# ============================================================================
# Test Executable: certificate_paths_test
# Ensures certificate storage defaults to LocalAppData on Windows.
# ============================================================================
add_executable(certificate_paths_test
    certificate_paths_test.cpp
)

target_link_libraries(certificate_paths_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(certificate_paths_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(certificate_paths_test)

# ============================================================================
# Test Executable: crash_dump_paths_test
# Verifies canonical LocalAppData crash dump directory and naming.
# ============================================================================
add_executable(crash_dump_paths_test
    crash_dump_paths_test.cpp
)

target_link_libraries(crash_dump_paths_test
    PRIVATE
    exosend-core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(crash_dump_paths_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(crash_dump_paths_test)

# ============================================================================
# Test Executable: win_safe_file_test
# Tests Win32 HANDLE-based safe file creation/write and atomic rename helpers.
# ============================================================================
if(WIN32)
    add_executable(win_safe_file_test
        win_safe_file_test.cpp
    )

    target_link_libraries(win_safe_file_test
        PRIVATE
        exosend-core
        GTest::gtest
        GTest::gtest_main
    )

    target_include_directories(win_safe_file_test
        PRIVATE
        ${CMAKE_SOURCE_DIR}/include
    )

gtest_discover_tests(win_safe_file_test)
endif()

# ============================================================================
# Test Executable: dev_reset_args_test
# Tests argument parsing for developer-only reset tool.
# ============================================================================
add_executable(dev_reset_args_test
    dev_reset_args_test.cpp
)

target_link_libraries(dev_reset_args_test
    PRIVATE
    exosend-devutil
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(dev_reset_args_test
    PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(dev_reset_args_test)

# ============================================================================
# Test Summary
# ============================================================================
message(STATUS "")
message(STATUS "==================================================")
message(STATUS "ExoSend Unit Tests Configured")
message(STATUS "==================================================")
message(STATUS "  protocol_test          - ExoHeader serialization tests")
message(STATUS "  hash_test              - SHA-256 hashing tests")
message(STATUS "  atomic_file_test       - Atomic temp+rename file helper tests")
message(STATUS "  json_test              - Discovery beacon JSON tests")
message(STATUS "  integration_test       - Multi-NIC, GC, file transfer tests")
message(STATUS "  fault_injection_test   - Error handling and fault injection")
message(STATUS "  fingerprint_utils_test - Fingerprint normalization tests")
message(STATUS "  trust_store_test       - Trust store pairing and pinning tests")
message(STATUS "  queue_manager_test     - TransferQueueManager concurrency tests")
message(STATUS "  incoming_transfer_policy_test - Incoming auto-accept policy tests")
message(STATUS "  tls_callback_test      - TLS verify callback security tests (v0.3)")
message(STATUS "  trust_store_dpapi_test - Trust store DPAPI persistence semantics tests")
message(STATUS "  protected_blob_test    - DPAPI ProtectedBlob tests (v0.3, WIN32)")
message(STATUS "  windows_acl_test       - Windows ACL hardening helper tests (v0.3, WIN32)")
message(STATUS "  pairing_limiter_test        - PairingPromptLimiter rate-limit tests (v0.3)")
message(STATUS "  beacon_rate_limiter_test   - BeaconRateLimiter sliding-window tests (v0.3)")
message(STATUS "  beacon_security_test       - Beacon goodbye/flood/timestamp tests (v0.3)")
message(STATUS "  transfer_server_port_test  - TransferServer dynamic port tests (v0.3)")
message(STATUS "  discovery_port_test        - UDP pool bind and beacon field tests (v0.3)")
message(STATUS "  benchmark_tool             - Performance benchmarking tool")
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
