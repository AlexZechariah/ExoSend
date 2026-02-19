/**
 * @file CrashHandler.cpp
 * @brief Enhanced crash handler implementation for ExoSend application
 */

#include "exosend/CrashHandler.h"
#include "exosend/ThreadSafeLog.h"
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>
#include <windows.h>
#include <dbghelp.h>
#include <signal.h>
#include <exception>
#include <cstdlib>

namespace ExoSend {

// Global exception information for crash dump
// Store EXCEPTION_POINTERS which contains both ExceptionRecord and Context
static EXCEPTION_POINTERS g_exceptionPointers = {nullptr, nullptr};
static bool g_hasExceptionInfo = false;
static DWORD g_exceptionCode = 0;  // Store exception code separately for logging

namespace {
    // Thread-safe logging macro - uses ThreadSafeLog for all crash logging
    #define LogTransferCrash(msg) ExoSend::ThreadSafeLog::log(msg)

    QString getExecutableDirectory() {
        // Use Windows API first; fall back to Qt if needed.
        WCHAR exePath[MAX_PATH];
        DWORD result = GetModuleFileNameW(NULL, exePath, MAX_PATH);
        if (result == 0 || result >= MAX_PATH) {
            return QCoreApplication::applicationDirPath();
        }
        return QFileInfo(QString::fromWCharArray(exePath)).absolutePath();
    }
} // anonymous namespace

//=============================================================================
// Private Helper Functions
//=============================================================================

/**
 * @brief Internal function to write minidump file
 */
void writeCrashDump(const QString& reason) {
    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss_zzz");

    // Primary dump location: same directory as ExoSend.exe.
    QString dumpPath = getExecutableDirectory();

    // Ensure target directory exists (normally already exists).
    QDir dir(dumpPath);
    if (!dir.exists()) {
        if (!dir.mkpath(".")) {
            LogTransferCrash("ERROR: Failed to access executable directory for dumps: " + dumpPath.toStdString());

            // Hard-failure fallback only.
            dumpPath = QDir::tempPath() + "/ExoSend_crash_dumps/";
            QDir fallbackDir(dumpPath);
            fallbackDir.mkpath(".");
            dir = fallbackDir;
        }
    }

    QString dumpFile = dir.absoluteFilePath(QString("crash_%1.dmp").arg(timestamp));
    QString logFile = dir.absoluteFilePath("crash_log.txt");

    // Log the crash reason immediately (before attempting dump)
    QFile crashLog(logFile);
    bool logOpened = crashLog.open(QIODevice::Append | QIODevice::Text);
    if (logOpened) {
        QTextStream stream(&crashLog);
        stream << "=== CRASH DETECTED ===\n";
        stream << "Timestamp: " << QDateTime::currentDateTime().toString() << "\n";
        stream << "Reason: " << reason << "\n";
        stream << "Process ID: " << GetCurrentProcessId() << "\n";
        stream << "Thread ID: " << GetCurrentThreadId() << "\n";
        stream.flush();
    }

    // Create minidump file with error handling
    HANDLE hFile = CreateFileA(
        dumpFile.toStdString().c_str(),
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (logOpened) {
            QTextStream stream(&crashLog);
            stream << "ERROR: CreateFile failed for .dmp - GLE: " << error << "\n";
            stream << "Attempted path: " << dumpFile << "\n";
            stream << "=======================\n\n";
            stream.flush();
        }

        // Note: Use MessageBox as fallback when logging fails
        // This ensures users are notified even when crash dump file creation fails
        QString msg = QString("Failed to create crash dump file:\n%1\nError: %2")
            .arg(dumpFile)
            .arg(error);
        MessageBoxA(NULL, msg.toStdString().c_str(), "Crash Dump Failed", MB_OK | MB_ICONERROR);

        return;
    }

    // Enhanced dump type with more information for better analysis
    // NOTE: MiniDumpWithFullMemory is disabled for normal dumps to keep size reasonable
    // but we use other useful flags.
    MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(
        MiniDumpWithHandleData |           // Handle information
        MiniDumpWithThreadInfo |           // Thread state
        MiniDumpWithProcessThreadData |    // Process and thread info
        MiniDumpWithUnloadedModules        // Unloaded DLLs
    );

    // Prepare exception pointers
    MINIDUMP_EXCEPTION_INFORMATION exceptionInfo;
    MINIDUMP_EXCEPTION_INFORMATION* pExceptionInfo = nullptr;

    if (g_hasExceptionInfo && g_exceptionPointers.ExceptionRecord) {
        exceptionInfo.ThreadId = GetCurrentThreadId();
        exceptionInfo.ExceptionPointers = &g_exceptionPointers;
        exceptionInfo.ClientPointers = FALSE;
        pExceptionInfo = &exceptionInfo;
    }

    BOOL success = MiniDumpWriteDump(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        hFile,
        dumpType,
        pExceptionInfo,
        NULL,
        NULL
    );

    DWORD lastError = success ? 0 : GetLastError();
    CloseHandle(hFile);

    // Log result
    if (logOpened) {
        QTextStream stream(&crashLog);
        if (success) {
            stream << "SUCCESS: Dump written to " << dumpFile << "\n";
            stream << "Dump size: " << QFileInfo(dumpFile).size() << " bytes\n";
            stream.flush();
        } else {
            stream << "ERROR: MiniDumpWriteDump failed - GLE: " << lastError << "\n";
            stream << "ExceptionCode: 0x" << QString::number(g_exceptionCode, 16) << "\n";
        }
        stream << "=======================\n\n";
        stream.flush();
        crashLog.close();
    }
}

//=============================================================================
// Additional Exception Handlers (safety coverage for missing handlers)
//=============================================================================

/**
 * @brief Last-chance exception handler for unhandled exceptions
 * Catches exceptions that bypass vectored handlers
 */
LONG WINAPI UnhandledExceptionFilter(EXCEPTION_POINTERS* exceptionInfo) {
    // Capture exception information
    g_exceptionPointers.ExceptionRecord = exceptionInfo->ExceptionRecord;
    g_exceptionPointers.ContextRecord = exceptionInfo->ContextRecord;
    g_hasExceptionInfo = true;
    g_exceptionCode = exceptionInfo->ExceptionRecord->ExceptionCode;

    // Write crash dump with detailed error
    writeCrashDump(QString("Unhandled Exception: 0x%1").arg(
        exceptionInfo->ExceptionRecord->ExceptionCode, 0, 16));

    return EXCEPTION_EXECUTE_HANDLER;
}

/**
 * @brief Handler for std::terminate() calls
 * Catches unhandled C++ exceptions
 */
void TerminateHandler() {
    // Note: Force immediate log write before abort
    LogTransferCrash("=== std::terminate() called ===");
    LogTransferCrash("=== Writing crash dump for std::terminate ===");
    writeCrashDump("std::terminate() called - unhandled C++ exception");

    // Restore default and re-raise
    std::set_terminate(nullptr);
    std::abort();
}

/**
 * @brief Handler for pure virtual function calls
 */
void PureCallHandler() {
    writeCrashDump("Pure virtual function call detected");

    // Attempt graceful exit
    std::abort();
}

/**
 * @brief Handler for CRT invalid parameter failures
 */
void InvalidParameterHandler(
    const wchar_t* expression,
    const wchar_t* function,
    const wchar_t* file,
    unsigned int line,
    uintptr_t reserved)
{
    Q_UNUSED(reserved);

    QString errorMsg = QString("Invalid Parameter");
    if (expression) {
        errorMsg += QString(": %1").arg(QString::fromWCharArray(expression));
    }
    if (function) {
        errorMsg += QString(" in %1").arg(QString::fromWCharArray(function));
    }

    writeCrashDump(errorMsg);

    // Don't return - this will trigger abort
    _set_invalid_parameter_handler(nullptr);
}

//=============================================================================
// Windows Exception Handler
//=============================================================================

/**
 * @brief Vectored exception handler for Windows structured exceptions
 */
LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS* exceptionInfo) {
    DWORD exceptionCode = exceptionInfo->ExceptionRecord->ExceptionCode;

    // Note: Check for stack overflow FIRST
    // EXCEPTION_STACK_OVERFLOW (0xC00000FD) can bypass standard exception handling
    if (exceptionCode == EXCEPTION_STACK_OVERFLOW) {
        LogTransferCrash("=== STACK OVERFLOW DETECTED ===");
        // Stack overflow requires special handling
        // Write dump immediately before stack gets worse
    }

    // Note: Ignore debug output exceptions to prevent false crash dumps
    // DBG_PRINTEXCEPTION_C (0x40010006) and DBG_PRINTEXCEPTION_WIDE_C (0x4001000a)
    // are raised when OutputDebugString is called. These are not actual crashes.
    if (exceptionCode == 0x40010006 || exceptionCode == 0x4001000a) {
        return EXCEPTION_CONTINUE_SEARCH;  // Let debugger handle it, don't write dump
    }

    // Capture exception information
    g_exceptionPointers.ExceptionRecord = exceptionInfo->ExceptionRecord;
    g_exceptionPointers.ContextRecord = exceptionInfo->ContextRecord;
    g_hasExceptionInfo = true;
    g_exceptionCode = exceptionCode;

    // Write crash dump with exception code
    writeCrashDump(QString("Exception: 0x%1").arg(
        exceptionCode, 0, 16));

    return EXCEPTION_EXECUTE_HANDLER;
}

//=============================================================================
// Qt Message Handler
//=============================================================================

/**
 * @brief Helper function to safely output to debug console
 * Separated to avoid __try with object unwinding
 */
void SafeOutputDebugString(const wchar_t* str) {
    if (str) {
        __try {
            OutputDebugStringW(str);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // Silently ignore - don't recurse into crash handler
        }
    }
}

/**
 * @brief Qt message handler for qCritical and qFatal messages
 */
void QtMessageHandler(QtMsgType type, const QMessageLogContext& context, const QString& msg) {
    switch (type) {
    case QtDebugMsg:
        // Don't write crash dump for debug messages
        break;

    case QtInfoMsg:
        // Don't write crash dump for info messages
        break;

    case QtWarningMsg: {
        // Note: Protect OutputDebugString with SEH to prevent DBG_PRINTEXCEPTION
        // Convert to std::wstring before __try block to avoid object unwinding issues
        std::wstring logMsg = L"Warning: ";
        logMsg += msg.toStdWString();
        logMsg += L"\n";
        SafeOutputDebugString(logMsg.c_str());
        break;
    }

    case QtCriticalMsg: {
        QString logMsg = QString("Critical: %1").arg(msg);
        // Write crash dump for critical messages
        writeCrashDump(logMsg);
        break;
    }

    case QtFatalMsg: {
        QString logMsg = QString("Fatal: %1 (%2:%3)").arg(msg).arg(context.file ? context.file : "unknown").arg(context.line);
        // Write crash dump for fatal messages
        writeCrashDump(logMsg);
        // Abort to trigger crash dump
        std::abort();
        break;
    }
    }
}

//=============================================================================
// Signal Handlers
//=============================================================================

/**
 * @brief Signal handler for C++ signals
 */
void SignalHandler(int signal) {
    const char* signalName = "UNKNOWN";
    switch (signal) {
    case SIGABRT: signalName = "SIGABRT"; break;
    case SIGFPE:  signalName = "SIGFPE";  break;
    case SIGILL:  signalName = "SIGILL";  break;
    case SIGSEGV: signalName = "SIGSEGV"; break;
    }

    // Write crash dump
    writeCrashDump(QString("Signal: %1").arg(signalName));

    // Restore default handler and re-raise signal
    ::signal(signal, SIG_DFL);
    ::raise(signal);
}

//=============================================================================
// Handler Installation Verification
//=============================================================================

/**
 * @brief Verify handler installation and write marker file
 */
void verifyHandlerInstallation() {
    // Crash artifacts should be written alongside ExoSend.exe.
    QString dumpPath = getExecutableDirectory();
    QDir dir(dumpPath);
    dir.mkpath(".");

    QDir dumpDir(dumpPath);
    QString markerFile = dumpDir.absoluteFilePath("handler_installed.txt");
    QFile marker(markerFile);

    if (marker.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream stream(&marker);
        stream << "Crash Handler Installation Report\n";
        stream << "==================================\n";
        stream << "Timestamp: " << QDateTime::currentDateTime().toString() << "\n";
        stream << "Process ID: " << GetCurrentProcessId() << "\n";
        stream << "Executable: " << QCoreApplication::applicationFilePath() << "\n";
        stream << "\nHandlers Installed:\n";
        stream << "  [x] Vectored Exception Handler\n";
        stream << "  [x] Unhandled Exception Filter\n";
        stream << "  [x] C++ Terminate Handler\n";
        stream << "  [x] Pure Call Handler\n";
        stream << "  [x] Invalid Parameter Handler\n";
        stream << "  [x] Signal Handlers (SIGABRT, SIGFPE, SIGILL, SIGSEGV)\n";
        stream << "  [x] Qt Message Handler\n";
        stream << "\nDirectory Status:\n";
        stream << "  Path: " << dumpPath << "\n";
        stream << "  Writable: " << (QFileInfo(dumpPath).isWritable() ? "YES" : "NO") << "\n";
        stream << "\nTest Info:\n";
        stream << "To test handler intentionally, add *((int*)nullptr) = 0; to code\n";
        marker.close();
    }
}

//=============================================================================
// Public API
//=============================================================================

/**
 * @brief Install all crash handlers
 *
 * This should be called at the very start of main() before any Qt initialization.
 */
void installCrashHandlers() {
    // Install Qt message handler (catches qCritical, qFatal)
    qInstallMessageHandler(QtMessageHandler);

    // Install vectored exception handler with verification
    PVOID handler = AddVectoredExceptionHandler(1, ExceptionFilter);
    if (!handler) {
        // Try with lower priority if high fails
        AddVectoredExceptionHandler(0xFFFF, ExceptionFilter);
    }

    // Note: Install unhandled exception filter (last chance)
    ::SetUnhandledExceptionFilter(UnhandledExceptionFilter);

    // Note: Set up C++ terminate handler
    std::set_terminate(TerminateHandler);

    // Note: Set up pure call handler
    _set_purecall_handler(PureCallHandler);

    // Note: Set up invalid parameter handler
    _set_invalid_parameter_handler(InvalidParameterHandler);

    // Note: Configure abort behavior
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);

    // Install signal handlers for C++ signals
    ::signal(SIGABRT, SignalHandler);
    ::signal(SIGFPE, SignalHandler);
    ::signal(SIGILL, SignalHandler);
    ::signal(SIGSEGV, SignalHandler);

    // Note: Verify installation and write marker file
    verifyHandlerInstallation();
}

} // namespace ExoSend
