/**
 * @file FileTransfer.cpp
 * @brief Binary file transfer protocol implementation
 */

#include "exosend/FileTransfer.h"
#include "exosend/TlsSocket.h"

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

FileSender::FileSender(const std::string& filePath)
    : m_filePath(filePath)
    , m_fileSize(0)
    , m_hashComputed(false)
{
    std::memset(m_sha256Hash, 0, sizeof(m_sha256Hash));
}

bool FileSender::sendFile(SOCKET socket,
                           std::string& errorMsg,
                           ProgressCallback progress)
{
    // Step 1: Initialize (validate file, get size)
    if (!initialize(errorMsg)) {
        return false;
    }

    // Step 2: Send offer header
    if (!sendOfferHeader(socket, errorMsg)) {
        return false;
    }

    // Step 3: Wait for response
    PacketType response;
    if (!waitForResponse(socket, response, errorMsg)) {
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
    if (!sendFileData(socket, errorMsg, progress)) {
        return false;
    }

    // Hash is now computed
    m_sha256HashString = HashUtils::hashToString(m_sha256Hash);
    m_hashComputed = true;

    return true;
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

bool FileSender::sendOfferHeader(SOCKET socket, std::string& errorMsg)
{
    // Create offer header
    ExoHeader offer(PacketType::OFFER, m_fileSize, m_fileName);

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
    if (!sendExact(socket, buffer.data(), HEADER_SIZE, errorMsg)) {
        errorMsg = "Failed to send offer header: " + errorMsg;
        return false;
    }

    return true;
}

bool FileSender::waitForResponse(SOCKET socket, PacketType& response,
                                  std::string& errorMsg)
{
    // Receive response header
    std::vector<uint8_t> buffer(HEADER_SIZE);
    if (!recvExact(socket, buffer.data(), HEADER_SIZE, errorMsg)) {
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

bool FileSender::sendFileData(SOCKET socket, std::string& errorMsg,
                               ProgressCallback progress)
{
    // Open file for reading
    std::ifstream file(m_filePath, std::ios::binary);
    if (!file) {
        errorMsg = "Failed to open file for reading: " + m_filePath;
        return false;
    }

    // Allocate buffer
    std::vector<uint8_t> buffer(BUFFER_SIZE);
    uint64_t totalSent = 0;
    int retryCount = 0;

    while (file) {
        // Read chunk from file
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize bytesRead = file.gcount();

        if (bytesRead <= 0) {
            break;  // EOF or error
        }

        // Send chunk
        size_t chunkSent = 0;
        while (chunkSent < static_cast<size_t>(bytesRead)) {
            int sendResult = send(socket,
                                  reinterpret_cast<const char*>(buffer.data() + chunkSent),
                                  static_cast<int>(bytesRead - chunkSent),
                                  0);

            if (sendResult == SOCKET_ERROR) {
                errorMsg = "send() failed: " + std::to_string(WSAGetLastError());
                return false;
            }

            if (sendResult == 0) {
                errorMsg = "Connection closed by peer";
                return false;
            }

            chunkSent += static_cast<size_t>(sendResult);
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

        // Reset retry count on successful chunk
        retryCount = 0;
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
    // Close file if still open
    if (m_outputFile.is_open()) {
        m_outputFile.close();
    }
}

FileReceiver::FileReceiver(FileReceiver&&) noexcept = default;

FileReceiver& FileReceiver::operator=(FileReceiver&&) noexcept = default;

bool FileReceiver::receiveFile(SOCKET socket,
                                std::string& errorMsg,
                                std::function<bool(const ExoHeader&)> acceptCallback,
                                ProgressCallback progress)
{
    // Step 1: Receive offer header
    ExoHeader offer;
    if (!receiveOfferHeader(socket, offer, errorMsg)) {
        return false;
    }

    // Step 2: Check if user accepts
    bool accepted = true;
    if (acceptCallback) {
        accepted = acceptCallback(offer);
    }

    // Step 3: Send response
    PacketType responseType = accepted ? PacketType::ACCEPT : PacketType::REJECT;
    if (!sendResponse(socket, responseType, errorMsg)) {
        return false;
    }

    if (!accepted) {
        errorMsg = "File transfer rejected by user";
        return false;
    }

    // Step 4: Validate download path for security
    if (!validateDownloadPath(m_downloadDir)) {
        errorMsg = "Invalid download directory path";
        sendResponse(socket, PacketType::REJECT, errorMsg);
        return false;
    }

    // Step 5: Check disk space
    if (!hasEnoughDiskSpace(offer.fileSize, m_downloadDir)) {
        errorMsg = "Insufficient disk space";
        sendResponse(socket, PacketType::REJECT, errorMsg);
        return false;
    }

    // Step 6: Receive file data
    if (!receiveFileData(socket, offer, errorMsg, progress)) {
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

    return true;
}

bool FileReceiver::receiveFile(SOCKET socket,
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
    if (!receiveFileData(socket, preReceivedHeader, errorMsg, progress)) {
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

    return true;
}

bool FileReceiver::receiveOfferHeader(SOCKET socket, ExoHeader& header,
                                       std::string& errorMsg)
{
    // Receive header
    std::vector<uint8_t> buffer(HEADER_SIZE);
    if (!recvExact(socket, buffer.data(), HEADER_SIZE, errorMsg)) {
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

bool FileReceiver::sendResponse(SOCKET socket, PacketType responseType,
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
    if (!sendExact(socket, buffer.data(), HEADER_SIZE, errorMsg)) {
        errorMsg = "Failed to send response header: " + errorMsg;
        return false;
    }

    return true;
}

bool FileReceiver::receiveFileData(SOCKET socket, const ExoHeader& header,
                                     std::string& errorMsg,
                                     ProgressCallback progress)
{
    // Generate unique filename
    m_outputPath = generateUniqueFilename(m_downloadDir, m_fileName);

    // Open output file
    m_outputFile.open(m_outputPath, std::ios::binary);
    if (!m_outputFile) {
        errorMsg = "Failed to create output file: " + m_outputPath;
        return false;
    }
    m_fileCreated = true;

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
        if (!recvExact(socket, buffer.data(), toRead, errorMsg)) {
            errorMsg = "Failed to receive file data: " + errorMsg;
            deletePartialFile();
            return false;
        }

        // Write to file
        m_outputFile.write(reinterpret_cast<const char*>(buffer.data()), toRead);
        if (!m_outputFile) {
            errorMsg = "Failed to write to file";
            deletePartialFile();
            return false;
        }

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
    m_outputFile.close();

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
    if (filename.empty()) {
        return false;
    }

    // Remove path separators
    size_t pos = 0;
    while ((pos = filename.find_first_of("/\\", pos)) != std::string::npos) {
        filename[pos] = '_';
    }

    // Remove relative path indicators
    pos = 0;
    while ((pos = filename.find("..", pos)) != std::string::npos) {
        filename.replace(pos, 2, "__");
    }

    // Remove drive letters (Windows)
    if (filename.length() >= 2 && filename[1] == ':') {
        filename[0] = '_';
    }

    // Check if filename is now empty or just dots
    if (filename.empty() || filename.find_first_not_of("._") == std::string::npos) {
        return false;
    }

    return true;
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
    if (m_fileCreated && !m_outputPath.empty()) {
        // Close file if open
        if (m_outputFile.is_open()) {
            m_outputFile.close();
        }

        // Delete file
        try {
            return std::filesystem::remove(m_outputPath);
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
