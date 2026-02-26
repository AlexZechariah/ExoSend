/**
 * @file FileTransfer.cpp
 * @brief Binary file transfer protocol implementation
 */

#include "exosend/FileTransfer.h"
#include "exosend/TlsSocket.h"
#include "exosend/TransportStream.h"
#include "exosend/AtomicFile.h"
#include "exosend/WindowsFilename.h"
#include "exosend/WinSafeFile.h"

#include <fstream>
#include <filesystem>
#include <iostream>
#include <algorithm>
#include <cstring>

// Undefine Windows macros that conflict with std::left, std::right, etc.
#ifdef left
#undef left
#endif
#ifdef right
#undef right
#endif

namespace ExoSend {

//=============================================================================
// TransportStream Implementations
//=============================================================================

bool PlainSocketStream::sendExact(const uint8_t* data, size_t size, std::string& errorMsg) {
    return ExoSend::sendExact(m_socket, data, size, errorMsg);
}

bool PlainSocketStream::recvExact(uint8_t* buffer, size_t size, std::string& errorMsg) {
    return ExoSend::recvExact(m_socket, buffer, size, errorMsg);
}

bool TlsTransportStream::sendExact(const uint8_t* data, size_t size, std::string& errorMsg) {
    return ExoSend::sendExact(m_tls, data, size, errorMsg);
}

bool TlsTransportStream::recvExact(uint8_t* buffer, size_t size, std::string& errorMsg) {
    return ExoSend::recvExact(m_tls, buffer, size, errorMsg);
}

void TlsTransportStream::shutdown() {
    m_tls.shutdown();
}

std::string TlsTransportStream::getPeerFingerprint(std::string& errorMsg) {
    return m_tls.getPeerFingerprint(errorMsg);
}

//=============================================================================
// Utility Functions
//=============================================================================

/**
 * @brief Send exact number of bytes
 * @param socket Socket to send to
 * @param data Data buffer
 * @param size Number of bytes
 * @param errorMsg Error message output
 * @return true if all bytes sent
 */
bool sendExact(SOCKET socket, const uint8_t* data, size_t size,
                std::string& errorMsg)
{
    if (!data || size == 0) {
        return true;  // Nothing to send
    }

    size_t totalSent = 0;
    const uint8_t* ptr = data;

    while (totalSent < size) {
        int sendResult = send(socket,
                              reinterpret_cast<const char*>(ptr + totalSent),
                              static_cast<int>(size - totalSent),
                              0);

        if (sendResult == SOCKET_ERROR) {
            errorMsg = "send() failed: " + std::to_string(WSAGetLastError());
            return false;
        }

        if (sendResult == 0) {
            errorMsg = "Connection closed by peer";
            return false;
        }

        totalSent += static_cast<size_t>(sendResult);
    }

    return true;
}

/**
 * @brief Set socket receive timeout
 * @param socket Socket to configure
 * @param timeoutMs Timeout in milliseconds
 * @return true if successful
 */
bool setSocketRecvTimeout(SOCKET socket, uint32_t timeoutMs) {
    DWORD timeout = timeoutMs;
    int result = setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                           reinterpret_cast<const char*>(&timeout),
                           sizeof(timeout));
    if (result == SOCKET_ERROR) {
        return false;
    }
    return true;
}

bool recvExact(SOCKET socket, uint8_t* buffer, size_t size,
                std::string& errorMsg)
{
    if (!buffer || size == 0) {
        return true;  // Nothing to receive
    }

    size_t totalReceived = 0;
    uint8_t* ptr = buffer;

    while (totalReceived < size) {
        int recvResult = recv(socket,
                              reinterpret_cast<char*>(ptr + totalReceived),
                              static_cast<int>(size - totalReceived),
                              0);

        if (recvResult == SOCKET_ERROR) {
            int wsaError = WSAGetLastError();
            if (wsaError == WSAETIMEDOUT) {
                errorMsg = "Receive timeout - peer not responding";
            } else {
                errorMsg = "recv() failed: " + std::to_string(wsaError);
            }
            return false;
        }

        if (recvResult == 0) {
            errorMsg = "Connection closed by peer";
            return false;
        }

        totalReceived += static_cast<size_t>(recvResult);
    }

    return true;
}

//=============================================================================
// FileSender Implementation
//=============================================================================

FileSender::FileSender(const std::string& filePath, const std::string& senderUuid)
    : m_filePath(filePath)
    , m_senderUuid(senderUuid)
    , m_fileSize(0)
    , m_hashComputed(false)
{
    std::memset(m_sha256Hash, 0, sizeof(m_sha256Hash));
}

bool FileSender::sendFile(SOCKET socket,
                           std::string& errorMsg,
                           ProgressCallback progress)
{
    PlainSocketStream stream(socket);
    return sendFile(stream, errorMsg, progress);
}

bool FileSender::sendFile(TransportStream& stream,
                           std::string& errorMsg,
                           ProgressCallback progress)
{
    // Step 1: Initialize (validate file, get size)
    if (!initialize(errorMsg)) {
        return false;
    }

    // Step 2: Send offer header
    if (!sendOfferHeader(stream, errorMsg)) {
        return false;
    }

    // Step 3: Wait for response
    PacketType response;
    if (!waitForResponse(stream, response, errorMsg)) {
        return false;
    }

    // Step 4: Check response
    if (response == PacketType::REJECT) {
        errorMsg = "File transfer rejected by receiver";
        return false;
    }

    if (response == PacketType::BUSY) {
        errorMsg = "Receiver is busy";
        return false;
    }

    if (response != PacketType::ACCEPT) {
        errorMsg = "Unexpected response: " +
                   std::to_string(static_cast<int>(response));
        return false;
    }

    // Step 5: Send file data
    if (!sendFileData(stream, errorMsg, progress)) {
        return false;
    }

    // Hash is now computed
    m_sha256HashString = HashUtils::hashToString(m_sha256Hash);
    m_hashComputed = true;

    // Step 6: Send final hash and require explicit receiver verification (v0.2.0+)
    {
        ExoHeader hashHeader(PacketType::HASH, 0, "");
        hashHeader.setSha256Bytes(m_sha256Hash);

        std::vector<uint8_t> hashBuffer(HEADER_SIZE);
        if (!hashHeader.serializeToBuffer(hashBuffer.data())) {
            errorMsg = "Failed to serialize hash header";
            return false;
        }

        if (!stream.sendExact(hashBuffer.data(), HEADER_SIZE, errorMsg)) {
            errorMsg = "Failed to send hash header: " + errorMsg;
            return false;
        }

        PacketType verifyResponse;
        if (!waitForResponse(stream, verifyResponse, errorMsg)) {
            errorMsg = "Failed to receive hash verification response: " + errorMsg;
            return false;
        }

        if (verifyResponse == PacketType::HASH_OK) {
            return true;
        }

        if (verifyResponse == PacketType::HASH_BAD) {
            errorMsg = "Receiver reported SHA-256 mismatch";
            return false;
        }

        errorMsg = "Unexpected hash verification response: " +
                   std::to_string(static_cast<int>(verifyResponse));
        return false;
    }
}

bool FileSender::initialize(std::string& errorMsg)
{
    try {
        // Extract filename from path
        size_t pos = m_filePath.find_last_of("/\\");
        if (pos != std::string::npos) {
            m_fileName = m_filePath.substr(pos + 1);
        } else {
            m_fileName = m_filePath;
        }

        // Check if file exists and can be opened
        std::ifstream file(m_filePath, std::ios::binary | std::ios::ate);
        if (!file) {
            DWORD dwError = GetLastError();
            errorMsg = "Failed to open file: " + m_filePath +
                       " (GetLastError() = " + std::to_string(dwError) + ")";
            return false;
        }

        // Get file size
        m_fileSize = file.tellg();

        if (m_fileSize == 0) {
            errorMsg = "File is empty: " + m_filePath;
            return false;
        }

        // Close the file (will be reopened in sendFile)
        file.close();

        // Check if filename is too long
        if (m_fileName.length() > MAX_FILENAME_LENGTH) {
            errorMsg = "Filename too long (max " +
                       std::to_string(MAX_FILENAME_LENGTH) + " characters)";
            return false;
        }

        // Reset incremental hash
        if (!m_incrementalHash.reset()) {
            errorMsg = "Failed to initialize hash context";
            return false;
        }

        return true;

    } catch (const std::exception& e) {
        errorMsg = std::string("Exception in initialize: ") + e.what();
        return false;
    } catch (...) {
        errorMsg = "Unknown exception in FileSender::initialize";
        return false;
    }
}

bool FileSender::sendOfferHeader(TransportStream& stream, std::string& errorMsg)
{
    // Create offer header
    ExoHeader offer(PacketType::OFFER, m_fileSize, m_fileName);
    if (!m_senderUuid.empty()) {
        offer.setSenderUuid(m_senderUuid);
    }

    // Validate header
    if (!offer.isValid()) {
        errorMsg = "Internal error: Invalid header created";
        return false;
    }

    // Serialize to buffer
    std::vector<uint8_t> buffer(HEADER_SIZE);
    if (!offer.serializeToBuffer(buffer.data())) {
        errorMsg = "Failed to serialize header";
        return false;
    }

    // Send header
    if (!stream.sendExact(buffer.data(), HEADER_SIZE, errorMsg)) {
        errorMsg = "Failed to send offer header: " + errorMsg;
        return false;
    }

    return true;
}

bool FileSender::waitForResponse(TransportStream& stream, PacketType& response,
                                  std::string& errorMsg)
{
    // Receive response header
    std::vector<uint8_t> buffer(HEADER_SIZE);
    if (!stream.recvExact(buffer.data(), HEADER_SIZE, errorMsg)) {
        errorMsg = "Failed to receive response header: " + errorMsg;
        return false;
    }

    // Deserialize header
    ExoHeader responseHeader;
    if (!responseHeader.deserializeFromBuffer(buffer.data())) {
        errorMsg = "Failed to deserialize response header";
        return false;
    }

    // Validate response
    if (!responseHeader.isValid()) {
        errorMsg = "Invalid response header received";
        return false;
    }

    response = responseHeader.getPacketType();
    return true;
}

bool FileSender::sendFileData(TransportStream& stream, std::string& errorMsg,
                               ProgressCallback progress)
{
    // Open file for reading
    std::ifstream file(m_filePath, std::ios::binary);
    if (!file) {
        errorMsg = "Failed to open file for reading: " + m_filePath;
        return false;
    }

    // Increase file stream buffering for large sequential reads
    std::vector<char> fileIoBuffer(1024 * 1024);
    (void)file.rdbuf()->pubsetbuf(fileIoBuffer.data(), static_cast<std::streamsize>(fileIoBuffer.size()));

    // Allocate buffer
    std::vector<uint8_t> buffer(BUFFER_SIZE);
    uint64_t totalSent = 0;

    while (file) {
        // Read chunk from file
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize bytesRead = file.gcount();

        if (bytesRead <= 0) {
            break;  // EOF or error
        }

        // Send chunk (exact)
        if (!stream.sendExact(buffer.data(), static_cast<size_t>(bytesRead), errorMsg)) {
            errorMsg = "Failed to send file chunk: " + errorMsg;
            return false;
        }

        // Update hash
        if (!updateHash(buffer.data(), static_cast<size_t>(bytesRead))) {
            errorMsg = "Failed to update hash";
            return false;
        }

        // Update progress
        totalSent += static_cast<uint64_t>(bytesRead);
        if (progress) {
            double percentage = (static_cast<double>(totalSent) /
                                static_cast<double>(m_fileSize)) * 100.0;
            progress(totalSent, m_fileSize, percentage);
        }

    }

    // Check for read errors
    if (file.bad()) {
        errorMsg = "Error reading file";
        return false;
    }

    // Verify all bytes sent
    if (totalSent != m_fileSize) {
        errorMsg = "Size mismatch: sent " + std::to_string(totalSent) +
                   " but file size is " + std::to_string(m_fileSize);
        return false;
    }

    // Finalize hash
    if (!m_incrementalHash.finalize(m_sha256Hash)) {
        errorMsg = "Failed to finalize hash";
        return false;
    }

    return true;
}

bool FileSender::updateHash(const uint8_t* data, size_t size)
{
    return m_incrementalHash.update(data, size);
}

//=============================================================================
// FileReceiver Implementation
//=============================================================================

FileReceiver::FileReceiver(const std::string& downloadDir)
    : m_downloadDir(downloadDir)
    , m_bytesReceived(0)
    , m_hashComputed(false)
    , m_fileCreated(false)
    , m_sizeMismatch(false)
{
    std::memset(m_sha256Hash, 0, sizeof(m_sha256Hash));
}

FileReceiver::~FileReceiver()
{
#ifndef _WIN32
    // Close file if still open
    if (m_outputFile.is_open()) {
        m_outputFile.close();
    }
#endif
}

FileReceiver::FileReceiver(FileReceiver&&) noexcept = default;

FileReceiver& FileReceiver::operator=(FileReceiver&&) noexcept = default;

bool FileReceiver::receiveFile(SOCKET socket,
                                std::string& errorMsg,
                                std::function<bool(const ExoHeader&)> acceptCallback,
                                ProgressCallback progress)
{
    PlainSocketStream stream(socket);
    return receiveFile(stream, errorMsg, acceptCallback, progress);
}

bool FileReceiver::receiveFile(TransportStream& stream,
                                std::string& errorMsg,
                                std::function<bool(const ExoHeader&)> acceptCallback,
                                ProgressCallback progress)
{
    // Step 1: Receive offer header
    ExoHeader offer;
    if (!receiveOfferHeader(stream, offer, errorMsg)) {
        return false;
    }

    // Step 2: Check if user accepts
    bool accepted = true;
    if (acceptCallback) {
        accepted = acceptCallback(offer);
    }

    // Step 3: Send response
    PacketType responseType = accepted ? PacketType::ACCEPT : PacketType::REJECT;
    if (!sendResponse(stream, responseType, errorMsg)) {
        return false;
    }

    if (!accepted) {
        errorMsg = "File transfer rejected by user";
        return false;
    }

    // Step 4: Validate download path for security
    if (!validateDownloadPath(m_downloadDir)) {
        errorMsg = "Invalid download directory path";
        sendResponse(stream, PacketType::REJECT, errorMsg);
        return false;
    }

    // Step 5: Check disk space
    if (!hasEnoughDiskSpace(offer.fileSize, m_downloadDir)) {
        errorMsg = "Insufficient disk space";
        sendResponse(stream, PacketType::REJECT, errorMsg);
        return false;
    }

    // Step 6: Receive file data
    if (!receiveFileData(stream, offer, errorMsg, progress)) {
        return false;
    }

    // Step 7: Verify size
    if (m_bytesReceived != offer.fileSize) {
        m_sizeMismatch = true;
        errorMsg = "Size mismatch: received " + std::to_string(m_bytesReceived) +
                   " but expected " + std::to_string(offer.fileSize);
        deletePartialFile();
        return false;
    }

    // Hash is now computed
    m_sha256HashString = HashUtils::hashToString(m_sha256Hash);
    m_hashComputed = true;

    // Step 8: Receive sender hash and verify (v0.2.0+)
    {
        std::vector<uint8_t> buffer(HEADER_SIZE);
        if (!stream.recvExact(buffer.data(), HEADER_SIZE, errorMsg)) {
            errorMsg = "Failed to receive hash header: " + errorMsg;
            deletePartialFile();
            return false;
        }

        ExoHeader hashHeader;
        if (!hashHeader.deserializeFromBuffer(buffer.data())) {
            errorMsg = "Failed to deserialize hash header";
            deletePartialFile();
            return false;
        }

        if (!hashHeader.isValid() || hashHeader.getPacketType() != PacketType::HASH) {
            errorMsg = "Invalid hash header received";
            deletePartialFile();
            return false;
        }

        const auto senderHash = hashHeader.getSha256Bytes();
        const bool match = HashUtils::compareHashes(
            reinterpret_cast<const unsigned char*>(senderHash.data()),
            reinterpret_cast<const unsigned char*>(m_sha256Hash)
        );

        const PacketType responseType = match ? PacketType::HASH_OK : PacketType::HASH_BAD;
        std::string responseError;
        (void)sendResponse(stream, responseType, responseError);

        if (!match) {
            errorMsg = "SHA-256 mismatch: transfer corrupted or tampered";
            deletePartialFile();
            return false;
        }
    }

    // Atomic finalize: rename temp file into place only after hash verification.
    {
        std::string renameError;
        if (!atomicRenameToFinal(std::filesystem::path(m_tempOutputPath),
                                 std::filesystem::path(m_outputPath),
                                 renameError)) {
            errorMsg = "Failed to finalize received file: " + renameError;
            deletePartialFile();
            return false;
        }
        m_tempOutputPath.clear();
    }

    return true;
}

bool FileReceiver::receiveFile(SOCKET socket,
                                const ExoHeader& preReceivedHeader,
                                std::string& errorMsg,
                                std::function<bool(const ExoHeader&)> acceptCallback,
                                ProgressCallback progress)
{
    PlainSocketStream stream(socket);
    return receiveFile(stream, preReceivedHeader, errorMsg, acceptCallback, progress);
}

bool FileReceiver::receiveFile(TransportStream& stream,
                                const ExoHeader& preReceivedHeader,
                                std::string& errorMsg,
                                std::function<bool(const ExoHeader&)> acceptCallback,
                                ProgressCallback progress)
{
    // Step 1: Validate the pre-received header
    if (!preReceivedHeader.isValid()) {
        errorMsg = "Invalid pre-received header";
        return false;
    }

    // Step 2: Check packet type
    if (preReceivedHeader.getPacketType() != PacketType::OFFER) {
        errorMsg = "Expected OFFER packet, got " + preReceivedHeader.getPacketTypeString();
        return false;
    }

    // Step 3: Validate and sanitize filename
    m_fileName = preReceivedHeader.getFilename();
    if (!sanitizeFilename(m_fileName)) {
        errorMsg = "Invalid filename received";
        return false;
    }

    // Step 4: Check if user accepts
    // NOTE: The ACCEPT response was already sent by TransferServer!
    // This callback is just for final confirmation/initialization - we proceed directly to file data
    bool accepted = true;
    if (acceptCallback) {
        accepted = acceptCallback(preReceivedHeader);
    }

    if (!accepted) {
        errorMsg = "File transfer rejected by user";
        return false;
    }

    // Step 5: Validate download path for security
    if (!validateDownloadPath(m_downloadDir)) {
        errorMsg = "Invalid download directory path";
        return false;
    }

    // Step 6: Check disk space
    if (!hasEnoughDiskSpace(preReceivedHeader.fileSize, m_downloadDir)) {
        errorMsg = "Insufficient disk space";
        return false;
    }

    // Step 7: Receive file data
    // Socket is positioned correctly: TransferServer sent ACCEPT, sender is now sending FILE DATA
    if (!receiveFileData(stream, preReceivedHeader, errorMsg, progress)) {
        return false;
    }

    // Step 9: Verify size
    if (m_bytesReceived != preReceivedHeader.fileSize) {
        m_sizeMismatch = true;
        errorMsg = "Size mismatch: received " + std::to_string(m_bytesReceived) +
                   " but expected " + std::to_string(preReceivedHeader.fileSize);
        deletePartialFile();
        return false;
    }

    // Hash is now computed
    m_sha256HashString = HashUtils::hashToString(m_sha256Hash);
    m_hashComputed = true;

    // Step 9: Receive sender hash and verify (v0.2.0+)
    {
        std::vector<uint8_t> buffer(HEADER_SIZE);
        if (!stream.recvExact(buffer.data(), HEADER_SIZE, errorMsg)) {
            errorMsg = "Failed to receive hash header: " + errorMsg;
            deletePartialFile();
            return false;
        }

        ExoHeader hashHeader;
        if (!hashHeader.deserializeFromBuffer(buffer.data())) {
            errorMsg = "Failed to deserialize hash header";
            deletePartialFile();
            return false;
        }

        if (!hashHeader.isValid() || hashHeader.getPacketType() != PacketType::HASH) {
            errorMsg = "Invalid hash header received";
            deletePartialFile();
            return false;
        }

        const auto senderHash = hashHeader.getSha256Bytes();
        const bool match = HashUtils::compareHashes(
            reinterpret_cast<const unsigned char*>(senderHash.data()),
            reinterpret_cast<const unsigned char*>(m_sha256Hash)
        );

        const PacketType responseType = match ? PacketType::HASH_OK : PacketType::HASH_BAD;
        std::string responseError;
        (void)sendResponse(stream, responseType, responseError);

        if (!match) {
            errorMsg = "SHA-256 mismatch: transfer corrupted or tampered";
            deletePartialFile();
            return false;
        }
    }

    // Atomic finalize: rename temp file into place only after hash verification.
    {
        std::string renameError;
        if (!atomicRenameToFinal(std::filesystem::path(m_tempOutputPath),
                                 std::filesystem::path(m_outputPath),
                                 renameError)) {
            errorMsg = "Failed to finalize received file: " + renameError;
            deletePartialFile();
            return false;
        }
        m_tempOutputPath.clear();
    }

    return true;
}

bool FileReceiver::receiveOfferHeader(TransportStream& stream, ExoHeader& header,
                                       std::string& errorMsg)
{
    // Receive header
    std::vector<uint8_t> buffer(HEADER_SIZE);
    if (!stream.recvExact(buffer.data(), HEADER_SIZE, errorMsg)) {
        errorMsg = "Failed to receive offer header: " + errorMsg;
        return false;
    }

    // Deserialize header
    if (!header.deserializeFromBuffer(buffer.data())) {
        errorMsg = "Failed to deserialize offer header";
        return false;
    }

    // Validate header
    if (!header.isValid()) {
        errorMsg = "Invalid offer header received";
        return false;
    }

    // Check packet type
    if (header.getPacketType() != PacketType::OFFER) {
        errorMsg = "Expected OFFER packet, got " + header.getPacketTypeString();
        return false;
    }

    // Validate filename
    m_fileName = header.getFilename();
    if (!sanitizeFilename(m_fileName)) {
        errorMsg = "Invalid filename received";
        return false;
    }

    return true;
}

bool FileReceiver::sendResponse(TransportStream& stream, PacketType responseType,
                                  std::string& errorMsg)
{
    // Create response header
    ExoHeader response(responseType, 0, "");

    // Serialize to buffer
    std::vector<uint8_t> buffer(HEADER_SIZE);
    if (!response.serializeToBuffer(buffer.data())) {
        errorMsg = "Failed to serialize response header";
        return false;
    }

    // Send response
    if (!stream.sendExact(buffer.data(), HEADER_SIZE, errorMsg)) {
        errorMsg = "Failed to send response header: " + errorMsg;
        return false;
    }

    return true;
}

bool FileReceiver::receiveFileData(TransportStream& stream, const ExoHeader& header,
                                      std::string& errorMsg,
                                      ProgressCallback progress)
{
    // Generate unique filename
    m_outputPath = generateUniqueFilename(m_downloadDir, m_fileName);
    const AtomicFilePaths paths = computeAtomicFilePaths(std::filesystem::path(m_outputPath));
    m_tempOutputPath = paths.tempPath.string();

    // Open output file exclusively (CREATE_NEW) for defense-in-depth.
#ifdef _WIN32
    {
        void* h = nullptr;
        std::wstring finalResolved;
        const std::wstring tempWide = paths.tempPath.wstring();
        if (!createNewWinFileExclusive(tempWide, h, finalResolved, errorMsg)) {
            errorMsg = "Failed to create output file: " + m_tempOutputPath + " (" + errorMsg + ")";
            return false;
        }

        std::wstring dirResolved;
        const std::wstring dirWide = std::filesystem::path(m_downloadDir).wstring();
        if (!getFinalPathForDirectory(dirWide, dirResolved, errorMsg)) {
            closeWinFile(h);
            errorMsg = "Failed to resolve download directory path: " + errorMsg;
            return false;
        }

        auto ensureTrailingBackslash = [](std::wstring& s) {
            if (!s.empty() && s.back() != L'\\' && s.back() != L'/') {
                s.push_back(L'\\');
            }
        };

        ensureTrailingBackslash(dirResolved);

        auto toUpper = [](std::wstring_view s) {
            std::wstring out;
            out.reserve(s.size());
            for (wchar_t ch : s) {
                if (ch >= L'a' && ch <= L'z') {
                    out.push_back(static_cast<wchar_t>(ch - (L'a' - L'A')));
                } else {
                    out.push_back(ch);
                }
            }
            return out;
        };

        const std::wstring dirUpper = toUpper(dirResolved);
        const std::wstring fileUpper = toUpper(finalResolved);

        if (fileUpper.rfind(dirUpper, 0) != 0) {
            closeWinFile(h);
            (void)std::filesystem::remove(paths.tempPath);
            errorMsg = "Resolved output path is outside download directory (reparse/path confusion)";
            return false;
        }

        m_outputHandle.handle = h;
        m_fileCreated = true;
    }
#else
    m_outputFile.open(m_tempOutputPath, std::ios::binary);
    if (!m_outputFile) {
        errorMsg = "Failed to create output file: " + m_tempOutputPath;
        return false;
    }
    m_fileCreated = true;

    // Increase file stream buffering for large sequential writes
    std::vector<char> outIoBuffer(1024 * 1024);
    (void)m_outputFile.rdbuf()->pubsetbuf(outIoBuffer.data(), static_cast<std::streamsize>(outIoBuffer.size()));
#endif

    // Reset hash
    if (!m_incrementalHash.reset()) {
        errorMsg = "Failed to initialize hash context";
        return false;
    }

    // Receive file data
    std::vector<uint8_t> buffer(BUFFER_SIZE);
    m_bytesReceived = 0;
    uint64_t expectedSize = header.fileSize;

    while (m_bytesReceived < expectedSize) {
        // Calculate how much to read
        size_t toRead = BUFFER_SIZE;
        uint64_t remaining = expectedSize - m_bytesReceived;
        if (remaining < static_cast<uint64_t>(BUFFER_SIZE)) {
            toRead = static_cast<size_t>(remaining);
        }

        // Receive chunk
        if (!stream.recvExact(buffer.data(), toRead, errorMsg)) {
            errorMsg = "Failed to receive file data: " + errorMsg;
            deletePartialFile();
            return false;
        }

        // Write to file
#ifdef _WIN32
        if (!writeAllWinFile(m_outputHandle.handle, buffer.data(), toRead, errorMsg)) {
            errorMsg = "Failed to write to file: " + errorMsg;
            deletePartialFile();
            return false;
        }
#else
        m_outputFile.write(reinterpret_cast<const char*>(buffer.data()), toRead);
        if (!m_outputFile) {
            errorMsg = "Failed to write to file";
            deletePartialFile();
            return false;
        }
#endif

        // Update hash
        if (!updateHash(buffer.data(), toRead)) {
            errorMsg = "Failed to update hash";
            deletePartialFile();
            return false;
        }

        // Update progress
        m_bytesReceived += static_cast<uint64_t>(toRead);
        if (progress) {
            double percentage = (static_cast<double>(m_bytesReceived) /
                                static_cast<double>(expectedSize)) * 100.0;
            progress(m_bytesReceived, expectedSize, percentage);
        }
    }

    // Close file
#ifdef _WIN32
    closeWinFile(m_outputHandle.handle);
#else
    m_outputFile.close();
#endif

    // Finalize hash
    if (!m_incrementalHash.finalize(m_sha256Hash)) {
        errorMsg = "Failed to finalize hash";
        deletePartialFile();
        return false;
    }

    return true;
}

bool FileReceiver::sanitizeFilename(std::string& filename)
{
    return sanitizeWindowsFilenameInPlace(filename);
}

std::string FileReceiver::generateUniqueFilename(const std::string& directory,
                                                  std::string& filename)
{
    std::string fullPath = directory + "\\" + filename;

    // Check if file exists
    int counter = 1;
    while (std::filesystem::exists(fullPath)) {
        // Find extension
        size_t dotPos = filename.find_last_of('.');
        std::string name;
        std::string ext;

        if (dotPos != std::string::npos) {
            name = filename.substr(0, dotPos);
            ext = filename.substr(dotPos);
        } else {
            name = filename;
            ext = "";
        }

        // Try new name
        fullPath = directory + "\\" + name + " (" + std::to_string(counter) + ")" + ext;
        counter++;
    }

    return fullPath;
}

bool FileReceiver::deletePartialFile()
{
    const std::string pathToDelete = !m_tempOutputPath.empty() ? m_tempOutputPath : m_outputPath;

    if (m_fileCreated && !pathToDelete.empty()) {
        // Close file if open
#ifdef _WIN32
        closeWinFile(m_outputHandle.handle);
#else
        if (m_outputFile.is_open()) {
            m_outputFile.close();
        }
#endif

        // Delete file
        try {
            return std::filesystem::remove(pathToDelete);
        } catch (...) {
            return false;
        }
    }
    return true;
}

bool FileReceiver::updateHash(const uint8_t* data, size_t size)
{
    return m_incrementalHash.update(data, size);
}

bool FileReceiver::hasEnoughDiskSpace(uint64_t requiredBytes,
                                       const std::string& directory)
{
    try {
        std::filesystem::space_info space = std::filesystem::space(directory);
        return space.available >= static_cast<int64_t>(requiredBytes);
    } catch (...) {
        // Assume there's enough space if we can't check
        return true;
    }
}

bool FileReceiver::validateDownloadPath(const std::string& downloadDir)
{
    if (downloadDir.empty()) {
        return false;
    }

    try {
        // Convert to absolute path
        std::filesystem::path dirPath = std::filesystem::absolute(downloadDir);
        std::string dirStr = dirPath.string();

        // Check for path traversal in directory path
        if (dirStr.find("..") != std::string::npos) {
            return false;
        }

        // Check for encoded traversal attempts
        if (dirStr.find("%2e%2e") != std::string::npos ||
            dirStr.find("%252e%252e") != std::string::npos) {
            return false;
        }

        // Verify directory exists
        std::error_code ec;
        if (!std::filesystem::exists(dirPath, ec) || ec) {
            return false;
        }

        return true;
    } catch (...) {
        return false;
    }
}

//=============================================================================
// TLS Utility Functions
//=============================================================================

/**
 * @brief Send exact number of bytes over TLS connection
 * @param tls TlsSocket wrapper
 * @param data Data to send
 * @param size Number of bytes to send
 * @param errorMsg Output error message
 * @return true if all bytes sent successfully
 *
 * Wrapper for TlsSocket::sendExact() for TLS-protected transfers.
 */
bool sendExact(TlsSocket& tls, const uint8_t* data, size_t size,
                std::string& errorMsg)
{
    return tls.sendExact(data, size, errorMsg);
}

/**
 * @brief Receive exact number of bytes from TLS connection
 * @param tls TlsSocket wrapper
 * @param buffer Buffer to receive data
 * @param size Number of bytes to receive
 * @param errorMsg Output error message
 * @return true if all bytes received successfully
 *
 * Wrapper for TlsSocket::recvExact() for TLS-protected transfers.
 */
bool recvExact(TlsSocket& tls, uint8_t* buffer, size_t size,
                std::string& errorMsg)
{
    return tls.recvExact(buffer, size, errorMsg);
}

}  // namespace ExoSend
