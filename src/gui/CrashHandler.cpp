/**
 * @file CrashHandler.cpp
 * @brief Enhanced crash handler implementation for ExoSend application
 */

#include "exosend/CrashHandler.h"
#include "exosend/CrashDumpPaths.h"
#include "exosend/ThreadSafeLog.h"
#include "exosend/WinSafeFile.h"
#include "exosend/WindowsAcl.h"
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
#include <filesystem>
#include <string>

namespace ExoSend {

// Global exception information for crash dump
// Store EXCEPTION_POINTERS which contains both ExceptionRecord and Context
static EXCEPTION_POINTERS g_exceptionPointers = {nullptr, nullptr};
static bool g_hasExceptionInfo = false;
static DWORD g_exceptionCode = 0;  // Store exception code separately for logging
static bool g_crashDumpsEnabled = true;

namespace {
    // Thread-safe logging macro - uses ThreadSafeLog for all crash logging
    #define LogTransferCrash(msg) ExoSend::ThreadSafeLog::log(msg)

    bool parseBoolEnvVar(const char* key, bool& outValue) {
        outValue = true;
        char buf[64] = {0};
        const DWORD n = GetEnvironmentVariableA(key, buf, static_cast<DWORD>(sizeof(buf)));
        if (n == 0 || n >= sizeof(buf)) {
            return false;
        }

        std::string v(buf);
        for (char& c : v) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));

        if (v == "1" || v == "true" || v == "yes" || v == "on") {
            outValue = true;
            return true;
        }
        if (v == "0" || v == "false" || v == "no" || v == "off") {
            outValue = false;
            return true;
        }
        return false;
    }

    bool ensureCrashDumpDirectory(std::wstring& outFinalDir, std::string& errorMsg) {
        errorMsg.clear();
        outFinalDir.clear();

        const auto dir = ExoSend::CrashDumpPaths::dumpDir();
        if (dir.empty()) {
            errorMsg = "Crash dump dir resolution failed";
            return false;
        }

        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        if (ec) {
            errorMsg = "Failed to create crash dump directory";
            return false;
        }

        // Restrict directory ACL (defense-in-depth).
        std::wstring aclErr;
        (void)ExoSend::restrictPathToCurrentUser(dir.wstring(), &aclErr);

        // Resolve final dir path via handle.
        return ExoSend::getFinalPathForDirectory(dir.wstring(), outFinalDir, errorMsg);
    }

    bool writeCrashTextLog(const std::filesystem::path& logPath,
                           const QString& reason,
                           std::string& errorMsg) {
        errorMsg.clear();

        void* handle = nullptr;
        std::wstring finalPath;
        if (!ExoSend::createNewWinFileExclusive(logPath.wstring(), handle, finalPath, errorMsg)) {
            return false;
        }
        ExoSend::ScopedWinFile file(handle);

        const std::string content =
            "=== CRASH DETECTED ===\r\n"
            "Timestamp: " + QDateTime::currentDateTime().toString().toStdString() + "\r\n" +
            "Reason: " + reason.toStdString() + "\r\n" +
            "Process ID: " + std::to_string(static_cast<unsigned long long>(GetCurrentProcessId())) + "\r\n" +
            "Thread ID: " + std::to_string(static_cast<unsigned long long>(GetCurrentThreadId())) + "\r\n";

        return ExoSend::writeAllWinFile(file.handle,
                                       reinterpret_cast<const uint8_t*>(content.data()),
                                       content.size(),
                                       errorMsg);
    }
} // anonymous namespace

//=============================================================================
// Private Helper Functions
//=============================================================================

/**
 * @brief Internal function to write minidump file
 */
void writeCrashDump(const QString& reason) {
    if (!g_crashDumpsEnabled) {
        return;
    }

    QString timestamp = QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss_zzz");

    std::wstring finalDir;
    std::string dirErr;
    if (!ensureCrashDumpDirectory(finalDir, dirErr)) {
        LogTransferCrash("ERROR: Failed to prepare crash dump directory: " + dirErr);
        return;
    }

    const unsigned long pid = GetCurrentProcessId();
    const auto dumpPath = ExoSend::CrashDumpPaths::dumpFilePath(timestamp.toStdString(), pid);
    const auto logPath = ExoSend::CrashDumpPaths::logFilePath(timestamp.toStdString(), pid);

    // Write crash log first (best-effort).
    {
        std::string logErr;
        if (!writeCrashTextLog(logPath, reason, logErr)) {
            LogTransferCrash("ERROR: Failed to write crash log: " + logErr);
        }
    }

    // Create minidump file securely using CREATE_NEW semantics.
    void* dumpHandle = nullptr;
    std::wstring dumpFinalPath;
    std::string dumpErr;
    if (!ExoSend::createNewWinFileExclusive(dumpPath.wstring(), dumpHandle, dumpFinalPath, dumpErr)) {
        LogTransferCrash("ERROR: Failed to create crash dump file: " + dumpErr);
        return;
    }
    ExoSend::ScopedWinFile dumpFileHandle(dumpHandle);

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
        reinterpret_cast<HANDLE>(dumpFileHandle.handle),
        dumpType,
        pExceptionInfo,
        NULL,
        NULL
    );

    if (!success) {
        const DWORD lastError = GetLastError();
        LogTransferCrash("ERROR: MiniDumpWriteDump failed - GLE: " + std::to_string(lastError));
        LogTransferCrash("ERROR: ExceptionCode: 0x" + std::to_string(static_cast<unsigned long long>(g_exceptionCode)));
    } else {
        LogTransferCrash("SUCCESS: Dump written.");
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
    bool markerEnabled = false;
    if (!parseBoolEnvVar("EXOSEND_CRASH_HANDLER_MARKER", markerEnabled) || !markerEnabled) {
        return;
    }

    std::wstring finalDir;
    std::string dirErr;
    if (!ensureCrashDumpDirectory(finalDir, dirErr)) {
        return;
    }

    const unsigned long pid = GetCurrentProcessId();
    const QString ts = QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss_zzz");
    const auto markerPath = ExoSend::CrashDumpPaths::logFilePath(ts.toStdString(), pid);

    std::string err;
    (void)writeCrashTextLog(markerPath, "Crash Handler Installation Report (marker)", err);
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
    // Allow environment override very early for privacy (before settings load).
    bool envValue = true;
    if (parseBoolEnvVar("EXOSEND_ENABLE_CRASH_DUMPS", envValue)) {
        g_crashDumpsEnabled = envValue;
    }

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

void ExoSend::setCrashDumpsEnabled(bool enabled)
{
    g_crashDumpsEnabled = enabled;
}

bool ExoSend::crashDumpsEnabled()
{
    return g_crashDumpsEnabled;
}
