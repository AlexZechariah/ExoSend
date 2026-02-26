/**
 * @file main.cpp
 * @brief Qt application entry point for ExoSend GUI
 *
 * This file contains the main() function that bootstraps
 * the ExoSend Qt GUI application.
 *
 * (c) 2026 ExoSend Project
 * Licensed under MIT License
 */

#include "exosend/CrashHandler.h"
#include <QApplication>
#include <QSharedMemory>
#include "exosend/QtUi/MainWindow.h"
#include "exosend/QtUi/SettingsManager.h"
#include <exosend/config.h>
#include <QMessageBox>
#include <QDir>
#include <iostream>  // Required for std::cerr
#include <chrono>    // For build timestamp

// Windows crash dump generation
#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#endif

/**
 * @brief Application entry point
 * @param argc Argument count
 * @param argv Argument values
 * @return Application exit code
 *
 * Initializes the Qt application, loads settings,
 * creates the main window, and runs the event loop.
 */
int main(int argc, char* argv[])
{
    // Create Qt application
    QApplication app(argc, argv);

    // INSTALL CRASH HANDLERS
    // This provides crash dump generation for Qt messages, signals, and exceptions
    // (includes vectored exception handler, Qt message handler, and signal handlers)
    ExoSend::installCrashHandlers();

    // Set application metadata
    app.setApplicationName("ExoSend");
    app.setApplicationVersion("0.3.0");
    app.setOrganizationName("ExoSend");
    app.setOrganizationDomain("exosend.local");

    // Set application-wide icon
    app.setWindowIcon(QIcon(":/assets/icon.png"));

    // Note: Prevent Qt from quitting when last window closes
    // This prevents the application from exiting unexpectedly after
    // file transfer completion when dialogs are closed.
    // The application will now only exit when explicitly quit.
    app.setQuitOnLastWindowClosed(false);

    // Single instance detection using QSharedMemory
    QSharedMemory sharedMemory("ExoSendSingleInstance");

    // Try to create shared memory segment
    if (!sharedMemory.create(1)) {
        // Already exists - another instance is running
        QMessageBox::critical(
            nullptr,
            "ExoSend Already Running",
            "An instance of ExoSend is already running.\n\n"
            "Please check your system tray (bottom-right corner) "
            "for the ExoSend icon.",
            QMessageBox::Ok
        );
        return 1;
    }

    // Create settings manager
    // Note: MainWindow takes ownership of the SettingsManager via std::unique_ptr,
    // so we do not pass &app as parent to avoid double-delete.
    SettingsManager* settings = new SettingsManager(nullptr);

    // Load settings from file
    if (!settings->loadSettings()) {
        // Settings file doesn't exist or is corrupt - use defaults
    }

    // Apply crash dump privacy setting unless explicitly overridden by env var.
    // EXOSEND_ENABLE_CRASH_DUMPS is parsed inside installCrashHandlers() for very-early crashes.
    if (!qEnvironmentVariableIsSet("EXOSEND_ENABLE_CRASH_DUMPS")) {
        ExoSend::setCrashDumpsEnabled(settings->getEnableCrashDumps());
    }

    // Create main window with settings (MainWindow takes ownership)
    MainWindow* window = new MainWindow(settings, nullptr);

    // Note: Removed the window->destroyed to app.quit() connection
    // This connection was causing the application to exit silently when
    // race conditions in threading caused MainWindow to be destroyed.
    // The app will now properly stay running during file transfers.
    // Normal exit paths (File > Exit, tray icon quit, window close) still work.

    // Restore window geometry from previous session
    QByteArray geometry = settings->getWindowGeometry();
    if (!geometry.isEmpty()) {
        window->restoreGeometry(geometry);
    } else {
        // Default size and position
        window->resize(900, 600);
        window->move(100, 100);
    }

    // Show the window
    window->show();

    // Run the application event loop
    int result = app.exec();

    // Cleanup (Qt will handle child objects)
    return result;
}
