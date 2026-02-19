cmake_minimum_required(VERSION 3.20)
project(ExoSend VERSION 0.1.0 LANGUAGES CXX)

# Fail fast on Windows if the configured compiler is not MSVC.
if(WIN32 AND NOT MSVC)
    message(FATAL_ERROR
        "Windows builds must use MSVC. Detected CMAKE_CXX_COMPILER_ID='${CMAKE_CXX_COMPILER_ID}', "
        "CMAKE_CXX_COMPILER='${CMAKE_CXX_COMPILER}'. "
        "Configure with 'cmake --preset windows-debug' or 'cmake --preset windows-release'."
    )
endif()

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Find vcpkg packages
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Qt6 REQUIRED COMPONENTS Widgets)

# ============================================
# Test Executables
# ============================================
add_executable(echo_server
    src/cmd/echo_server.cpp
)

add_executable(echo_client
    src/cmd/echo_client.cpp
)

target_link_libraries(echo_server PRIVATE ws2_32)
target_link_libraries(echo_client PRIVATE ws2_32)

# ============================================
# Core Library
# ============================================
add_library(exosend-core STATIC
    src/core/DiscoveryService.cpp
    src/core/HashUtils.cpp
    src/core/FileTransfer.cpp
    src/core/TransferSession.cpp
    src/core/TransferServer.cpp
    src/core/TransferQueueManager.cpp
    src/core/TlsSocket.cpp
    src/core/CertificateManager.cpp
    src/core/ThreadSafeLog.cpp
)

target_include_directories(exosend-core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(exosend-core PUBLIC
    Ws2_32
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto
    OpenSSL::SSL
    Qt6::Core
)

# ============================================
# Test Programs
# ============================================
add_executable(discovery_test src/cmd/discovery_test.cpp)
add_executable(file_send_test src/cmd/file_send_test.cpp)
add_executable(file_receive_test src/cmd/file_receive_test.cpp)
add_executable(server_test src/cmd/server_test.cpp)

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
    src/gui/PeerListModel.cpp
    src/gui/PeerListItemDelegate.cpp
    src/gui/TransferListModel.cpp
    src/gui/SettingsManager.cpp
    src/gui/TrayIcon.cpp
    src/gui/SettingsDialog.cpp
    src/gui/IncomingTransferDialog.cpp
    src/gui/CloseWarningDialog.cpp
    src/gui/CrashHandler.cpp
    resources.qrc
)

set(GUI_HEADERS
    include/exosend/QtUi/MainWindow.h
    include/exosend/QtUi/DragDropListView.h
    include/exosend/QtUi/PeerListModel.h
    include/exosend/QtUi/PeerListItemDelegate.h
    include/exosend/QtUi/TransferListModel.h
    include/exosend/QtUi/SettingsManager.h
    include/exosend/QtUi/TrayIcon.h
    include/exosend/QtUi/SettingsDialog.h
    include/exosend/QtUi/IncomingTransferDialog.h
    include/exosend/QtUi/CloseWarningDialog.h
)

add_executable(ExoSend
    ${GUI_SOURCES}
    ${GUI_HEADERS}
    ExoSend.rc
)

# Link against Qt and core library
target_link_libraries(ExoSend PRIVATE
    Qt6::Widgets
    exosend-core
)

# Add debug symbols for crash dump analysis (Windows MSVC only)
if(MSVC)
    # Enable debug symbols in all configurations
    target_compile_options(ExoSend PRIVATE /Zi)
    # Generate PDB files for crash dump analysis
    set_target_properties(ExoSend PROPERTIES
        PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/Release"
        PDB_NAME "ExoSend"
    )
endif()

# Enable MOC for Qt signals/slots
set_target_properties(ExoSend PROPERTIES
    AUTOMOC ON
    AUTOUIC ON
    AUTORCC ON
)

# Windows: Console application (enabled for debugging)
if(WIN32)
    set_target_properties(ExoSend PROPERTIES
        WIN32_EXECUTABLE TRUE
    )

    # Deploy Qt dependencies - use CMAKE_BINARY_DIR for vcpkg paths with VS generator
    # Try windeployqt first (for Release builds)
	    find_program(WINDEPLOYQT_EXECUTABLE windeployqt
	        HINTS "${CMAKE_BINARY_DIR}/vcpkg_installed/x64-windows/tools/Qt6/bin"
	              "${CMAKE_SOURCE_DIR}/vcpkg_installed/x64-windows/tools/Qt6/bin"
	    )

	    # Manual DLL deployment as fallback (works with both Release and Debug)
	    # Use vcpkg toolchain's resolved installed dir so builds work even when
	    # VCPKG_INSTALLED_DIR is configured outside the build directory.
	    set(_EXOSEND_VCPKG_INSTALLED_DIR "${VCPKG_INSTALLED_DIR}")
	    if(NOT _EXOSEND_VCPKG_INSTALLED_DIR)
	        set(_EXOSEND_VCPKG_INSTALLED_DIR "${CMAKE_BINARY_DIR}/vcpkg_installed")
	    endif()

	    add_custom_command(TARGET ExoSend POST_BUILD
	        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:ExoSend>/platforms"
	        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:ExoSend>/styles"
	        COMMAND ${CMAKE_COMMAND} -E copy_if_different
	            "${_EXOSEND_VCPKG_INSTALLED_DIR}/x64-windows/Qt6/plugins/platforms/qwindows.dll"
	            "$<TARGET_FILE_DIR:ExoSend>/platforms/"
	        COMMAND ${CMAKE_COMMAND} -E copy_if_different
	            "${_EXOSEND_VCPKG_INSTALLED_DIR}/x64-windows/Qt6/plugins/styles/qmodernwindowsstyle.dll"
	            "$<TARGET_FILE_DIR:ExoSend>/styles/"
	        COMMAND ${CMAKE_COMMAND} -E copy_if_different
	            "${_EXOSEND_VCPKG_INSTALLED_DIR}/x64-windows/bin/Qt6Core.dll"
	            "$<TARGET_FILE_DIR:ExoSend>/"
	        COMMAND ${CMAKE_COMMAND} -E copy_if_different
	            "${_EXOSEND_VCPKG_INSTALLED_DIR}/x64-windows/bin/Qt6Gui.dll"
	            "$<TARGET_FILE_DIR:ExoSend>/"
	        COMMAND ${CMAKE_COMMAND} -E copy_if_different
	            "${_EXOSEND_VCPKG_INSTALLED_DIR}/x64-windows/bin/Qt6Widgets.dll"
	            "$<TARGET_FILE_DIR:ExoSend>/"
	        COMMAND ${CMAKE_COMMAND} -E copy_if_different
	            "${_EXOSEND_VCPKG_INSTALLED_DIR}/x64-windows/bin/libcrypto-3-x64.dll"
	            "$<TARGET_FILE_DIR:ExoSend>/"
	        COMMAND ${CMAKE_COMMAND} -E copy_if_different
	            "${_EXOSEND_VCPKG_INSTALLED_DIR}/x64-windows/bin/libssl-3-x64.dll"
	            "$<TARGET_FILE_DIR:ExoSend>/"
	        COMMENT "Deploying Qt plugins and required DLLs..."
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
    RUNTIME DESTINATION bin
)

install(TARGETS exosend-core
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/exosend
    DESTINATION include
)
