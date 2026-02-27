cmake_minimum_required(VERSION 3.20)
project(ExoSend VERSION 0.3.1 LANGUAGES CXX)

# Fail fast on Windows if the configured compiler is not MSVC.
if(WIN32 AND NOT MSVC)
    message(FATAL_ERROR
        "Windows builds must use MSVC. Detected CMAKE_CXX_COMPILER_ID='${CMAKE_CXX_COMPILER_ID}', "
        "CMAKE_CXX_COMPILER='${CMAKE_CXX_COMPILER}'. "
        "Configure with 'cmake --preset windows'."
    )
endif()

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Optional security hardening flags for MSVC builds.
option(EXOSEND_SECURITY_HARDENING "Enable MSVC security hardening flags" ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Find vcpkg packages
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# Qt6 may optionally look for Vulkan headers (WrapVulkanHeaders). ExoSend does not
# use Vulkan, and we want a clean configure without "Could NOT find" noise.
set(CMAKE_DISABLE_FIND_PACKAGE_WrapVulkanHeaders ON)
find_package(Qt6 REQUIRED COMPONENTS Widgets)

# Enforce a minimum Qt version for security/bugfix patch-level stability.
# The canonical build guide targets Qt 6.8.3.
if(Qt6_VERSION VERSION_LESS "6.8.3")
    message(FATAL_ERROR
        "Qt6 >= 6.8.3 is required. Detected Qt6_VERSION='${Qt6_VERSION}'. "
        "Update QT_ROOT_DIR / CI Qt install to a safe patch version."
    )
endif()

# MSVC hardening helper (applies /sdl and CFG).
function(exosend_enable_msvc_hardening target_name)
    if(MSVC AND EXOSEND_SECURITY_HARDENING)
        # /FS avoids PDB contention when /Zi is enabled and builds are parallel.
        target_compile_options(${target_name} PRIVATE /sdl /guard:cf /FS)
        if(TARGET ${target_name})
            # Enable Control Flow Guard at link time for executables/DLLs.
            get_target_property(_type ${target_name} TYPE)
            if(_type STREQUAL "EXECUTABLE" OR _type STREQUAL "SHARED_LIBRARY" OR _type STREQUAL "MODULE_LIBRARY")
                target_link_options(${target_name} PRIVATE /guard:cf)
            endif()
        endif()
    endif()
endfunction()

# ============================================
# Test Executables
# ============================================
add_executable(echo_server
    src/cmd/echo_server.cpp
)
exosend_enable_msvc_hardening(echo_server)

add_executable(echo_client
    src/cmd/echo_client.cpp
)
exosend_enable_msvc_hardening(echo_client)

add_library(exosend-devutil STATIC
    src/core/DevResetArgs.cpp
)
exosend_enable_msvc_hardening(exosend-devutil)

target_include_directories(exosend-devutil PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

add_executable(ExoSendFirewallHelper
    src/cmd/firewall_helper.cpp
)
exosend_enable_msvc_hardening(ExoSendFirewallHelper)

add_executable(ExoSendReset
    src/cmd/reset_tool.cpp
)
exosend_enable_msvc_hardening(ExoSendReset)

add_executable(ExoSendRelaunch
    src/cmd/relaunch_tool.cpp
    src/core/RelaunchArgs.cpp
)
exosend_enable_msvc_hardening(ExoSendRelaunch)

target_link_libraries(echo_server PRIVATE ws2_32)
target_link_libraries(echo_client PRIVATE ws2_32)
target_link_libraries(ExoSendFirewallHelper PRIVATE ole32 oleaut32)
target_link_libraries(ExoSendReset PRIVATE exosend-devutil Shell32)

# ============================================
# Core Library
# ============================================
add_library(exosend-core STATIC
    src/core/AtomicFile.cpp
    src/core/AppPaths.cpp
    src/core/BeaconRateLimiter.cpp
    src/core/ConnectionRateLimiter.cpp
    src/core/CrashDumpPaths.cpp
    src/core/DiscoveryService.cpp
    src/core/HashUtils.cpp
    src/core/FileTransfer.cpp
    src/core/MigrationUtils.cpp
    src/core/IncomingTransferPolicy.cpp
    src/core/PairingConfirm.cpp
    src/core/PairingPhrase.cpp
    src/core/PairingPhraseExtract.cpp
    src/core/PairingSecret.cpp
    src/core/WindowsFilename.cpp
    src/core/WinSafeFile.cpp
    src/core/TransferSession.cpp
    src/core/TransferServer.cpp
    src/core/TransferQueueManager.cpp
    src/core/TlsSocket.cpp
    src/core/CertificateManager.cpp
    src/core/TrustStore.cpp
    src/core/TrustStoreDpapi.cpp
    src/core/ThreadSafeLog.cpp
    src/core/ProtectedBlob.cpp
    src/core/PairingPromptLimiter.cpp
    src/core/WindowsAcl.cpp
)
exosend_enable_msvc_hardening(exosend-core)

target_include_directories(exosend-core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(exosend-core PUBLIC
    Ws2_32
    Bcrypt
    Crypt32
    Advapi32
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto
    OpenSSL::SSL
    Qt6::Core
)

# Dev tooling that depends on core utilities (paths, migration, etc.)
target_link_libraries(ExoSendReset PRIVATE exosend-core)

# ============================================
# Test Programs
# ============================================
add_executable(discovery_test src/cmd/discovery_test.cpp)
add_executable(file_send_test src/cmd/file_send_test.cpp)
add_executable(file_receive_test src/cmd/file_receive_test.cpp)
add_executable(server_test src/cmd/server_test.cpp)
exosend_enable_msvc_hardening(discovery_test)
exosend_enable_msvc_hardening(file_send_test)
exosend_enable_msvc_hardening(file_receive_test)
exosend_enable_msvc_hardening(server_test)

target_link_libraries(discovery_test PRIVATE exosend-core)
target_link_libraries(file_send_test PRIVATE exosend-core)
target_link_libraries(file_receive_test PRIVATE exosend-core)
target_link_libraries(server_test PRIVATE exosend-core)

# ============================================
# Qt GUI Application
# ============================================
set(GUI_SOURCES
    src/gui/main.cpp
    src/gui/MainWindow.cpp
    src/gui/DragDropListView.cpp
    src/gui/PlaceholderListView.cpp
    src/gui/PeerListModel.cpp
    src/gui/PeerListItemDelegate.cpp
    src/gui/TransferListModel.cpp
    src/gui/SettingsManager.cpp
    src/gui/TrayIcon.cpp
    src/gui/SettingsDialog.cpp
    src/gui/IncomingTransferDialog.cpp
    src/gui/SecurePairingIncomingDialog.cpp
    src/gui/SecurePairingOutgoingDialog.cpp
    src/gui/CloseWarningDialog.cpp
    src/gui/CrashHandler.cpp
)

set(GUI_HEADERS
    include/exosend/QtUi/MainWindow.h
    include/exosend/QtUi/DragDropListView.h
    include/exosend/QtUi/PlaceholderListView.h
    include/exosend/QtUi/PeerListModel.h
    include/exosend/QtUi/PeerListItemDelegate.h
    include/exosend/QtUi/TransferListModel.h
    include/exosend/QtUi/SettingsManager.h
    include/exosend/QtUi/TrayIcon.h
    include/exosend/QtUi/SettingsDialog.h
    include/exosend/QtUi/IncomingTransferDialog.h
    include/exosend/QtUi/SecurePairingIncomingDialog.h
    include/exosend/QtUi/SecurePairingOutgoingDialog.h
    include/exosend/QtUi/CloseWarningDialog.h
)

add_executable(ExoSend
    ${GUI_SOURCES}
    ${GUI_HEADERS}
    ExoSend.rc
)
exosend_enable_msvc_hardening(ExoSend)

# Link against Qt and core library
target_link_libraries(ExoSend PRIVATE
    Qt6::Widgets
    exosend-core
    Advapi32
    ole32
    uuid
)

# Add debug symbols for crash dump analysis (Windows MSVC only)
if(MSVC)
    # Debug symbols are enabled only for Debug/RelWithDebInfo to avoid:
    # - leaking extra implementation detail in Release binaries
    # - MSVC PDB contention issues under highly-parallel Release builds
    target_compile_options(ExoSend PRIVATE
        $<$<CONFIG:Debug>:/Zi>
        $<$<CONFIG:RelWithDebInfo>:/Zi>
    )
    # Generate PDB files (when enabled) for crash dump analysis
    set_target_properties(ExoSend PROPERTIES
        PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/Release"
        PDB_NAME "ExoSend"
    )
endif()

# Explicit Qt code generation (MOC/RCC). No .ui files are used, so UIC is not needed.
set(EXOSEND_MOC_HEADERS
    include/exosend/QtUi/CloseWarningDialog.h
    include/exosend/QtUi/DragDropListView.h
    include/exosend/QtUi/PlaceholderListView.h
    include/exosend/QtUi/IncomingTransferDialog.h
    include/exosend/QtUi/SecurePairingIncomingDialog.h
    include/exosend/QtUi/SecurePairingOutgoingDialog.h
    include/exosend/QtUi/MainWindow.h
    include/exosend/QtUi/PeerListItemDelegate.h
    include/exosend/QtUi/PeerListModel.h
    include/exosend/QtUi/SettingsDialog.h
    include/exosend/QtUi/SettingsManager.h
    include/exosend/QtUi/TransferListModel.h
    include/exosend/QtUi/TrayIcon.h
)
qt6_wrap_cpp(EXOSEND_MOC_SOURCES ${EXOSEND_MOC_HEADERS})
qt6_add_resources(EXOSEND_QRC_SOURCES resources.qrc)

# Avoid CMake AutoMoc/AutoRcc path. In some constrained environments, CMake's
# cmake_autogen step cannot spawn moc.exe (libuv EPERM). Add generated sources
# explicitly via target_sources.
target_sources(ExoSend PRIVATE
    ${EXOSEND_MOC_SOURCES}
    ${EXOSEND_QRC_SOURCES}
)

# Windows: GUI application + runtime deployment
if(WIN32)
    set_target_properties(ExoSend PROPERTIES
        WIN32_EXECUTABLE TRUE
    )

    # Locate windeployqt from the officially installed Qt6.
    # Qt6::qmake is exported by the Qt6 cmake package and lives in the same
    # bin/ directory as windeployqt.
    get_target_property(_qt_qmake_location Qt6::qmake IMPORTED_LOCATION)
    get_filename_component(QT_BIN_DIR "${_qt_qmake_location}" DIRECTORY)
    find_program(WINDEPLOYQT_EXECUTABLE windeployqt
        HINTS "${QT_BIN_DIR}"
        REQUIRED
    )
    message(STATUS "windeployqt: ${WINDEPLOYQT_EXECUTABLE}")

    # Deploy all Qt DLLs, platform plugins, ICU, etc. using windeployqt.
    # --release: deploy release-mode Qt DLLs only (no debug counterparts).
    # --no-translations: skip QM translation files (English-only app).
    # --no-system-d3d-compiler: not needed for a Widgets application.
    add_custom_command(TARGET ExoSend POST_BUILD
        COMMAND "${WINDEPLOYQT_EXECUTABLE}"
            --release
            --no-translations
            --no-system-d3d-compiler
            --no-compiler-runtime
            "$<TARGET_FILE:ExoSend>"
        COMMENT "Running windeployqt to deploy Qt runtime..."
    )

    # qmodernwindowsstyle.dll: style plugin not always auto-detected by
    # windeployqt binary scanning. Explicitly copy it as a guaranteed step.
    set(_QT_STYLES_DIR "${QT_BIN_DIR}/../plugins/styles")
    cmake_path(NORMAL_PATH _QT_STYLES_DIR)
    add_custom_command(TARGET ExoSend POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:ExoSend>/styles"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_QT_STYLES_DIR}/qmodernwindowsstyle.dll"
            "$<TARGET_FILE_DIR:ExoSend>/styles/qmodernwindowsstyle.dll"
        COMMENT "Deploying qmodernwindowsstyle plugin..."
    )

    # OpenSSL DLLs still come from vcpkg (not bundled with the Qt official installer).
    set(_VCPKG_INSTALLED "${VCPKG_INSTALLED_DIR}")
    if(NOT _VCPKG_INSTALLED)
        set(_VCPKG_INSTALLED "${CMAKE_SOURCE_DIR}/vcpkg_installed")
    endif()

    add_custom_command(TARGET ExoSend POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_VCPKG_INSTALLED}/x64-windows/bin/libcrypto-3-x64.dll"
            "$<TARGET_FILE_DIR:ExoSend>/libcrypto-3-x64.dll"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${_VCPKG_INSTALLED}/x64-windows/bin/libssl-3-x64.dll"
            "$<TARGET_FILE_DIR:ExoSend>/libssl-3-x64.dll"
        COMMENT "Deploying OpenSSL DLLs from vcpkg..."
    )
endif()

# ============================================
# Unit Tests
# ============================================
option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ============================================
# Installation
# ============================================
install(TARGETS echo_server echo_client discovery_test file_send_test file_receive_test server_test ExoSend
    ExoSendFirewallHelper
    RUNTIME DESTINATION bin
)

install(TARGETS exosend-core
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/exosend
    DESTINATION include
)
