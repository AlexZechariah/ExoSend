/**
 * @file FileTransfer.h
 * @brief Binary file transfer protocol implementation
 */

#pragma once

#include "config.h"
#include "TransferHeader.h"
#include "HashUtils.h"
#include <string>
#include <vector>
#include <cstdint>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <functional>
#include <fstream>
#include <filesystem>
#include "WinSafeFile.h"

namespace ExoSend {

// Forward declaration for TLS support
class TlsSocket;
class TransportStream;

/**
 * @brief Progress callback function type
 *
 * Called during file transfer to report progress.
 *
 * @param bytesTransferred Total bytes transferred so far
 * @param totalBytes Total file size
 * @param percentage Transfer percentage (0-100)
 */
using ProgressCallback = std::function<void(uint64_t bytesTransferred,
                                             uint64_t totalBytes,
                                             double percentage)>;

//=============================================================================
// FileSender Class
//=============================================================================

/**
 * @class FileSender
 * @brief Handles sending files over a TCP socket
 *
 * This class manages the sender side of file transfers:
 * 1. Sends an OFFER header to the receiver
 * 2. Waits for ACCEPT/REJECT/BUSY response
 * 3. If accepted, streams file data in 64KB chunks
 * 4. Computes SHA-256 hash during transfer
 *
 * Usage:
 * @code
 * FileSender sender("C:\\path\\to\\file.txt");
 * std::string error;
 * if (sender.sendFile(socket, error)) {
 *     std::cout << "File sent successfully\n";
 * } else {
 *     std::cout << "Error: " << error << "\n";
 * }
 * @endcode
 */
class FileSender {
public:
    /**
     * @brief Constructor
     * @param filePath Path to the file to send
     *
     * Does not open the file yet. Call sendFile() to initiate transfer.
     */
    explicit FileSender(const std::string& filePath, const std::string& senderUuid = {});

    /**
     * @brief Destructor
     */
    ~FileSender() = default;

    // Prevent copying
    FileSender(const FileSender&) = delete;
    FileSender& operator=(const FileSender&) = delete;

    // Allow moving
    FileSender(FileSender&&) noexcept = default;
    FileSender& operator=(FileSender&&) noexcept = default;

    /**
     * @brief Send the file over a connected TCP socket
     * @param socket Connected TCP socket
     * @param errorMsg Output error message if transfer fails
     * @param progress Optional progress callback (can be nullptr)
     * @return true if transfer successful, false otherwise
     *
     * This method performs the complete send operation:
     * 1. Validates the file exists and is readable
     * 2. Sends OFFER header with file metadata
     * 3. Waits for ACCEPT/REJECT/BUSY response
     * 4. If accepted, streams file in 64KB chunks
     * 5. Computes SHA-256 hash during transfer
     */
    bool sendFile(SOCKET socket,
                  std::string& errorMsg,
                  ProgressCallback progress = nullptr);

    /**
     * @brief Send the file over a connected transport (plain TCP or TLS)
     * @param stream Connected transport stream
     * @param errorMsg Output error message if transfer fails
     * @param progress Optional progress callback (can be nullptr)
     * @return true if transfer successful, false otherwise
     */
    bool sendFile(TransportStream& stream,
                  std::string& errorMsg,
                  ProgressCallback progress = nullptr);

    /**
     * @brief Get the source file path
     * @return File path
     */
    const std::string& getFilePath() const { return m_filePath; }

    /**
     * @brief Get the filename (without path)
     * @return Filename
     */
    const std::string& getFileName() const { return m_fileName; }

    /**
     * @brief Get the file size in bytes
     * @return File size
     */
    uint64_t getFileSize() const { return m_fileSize; }

    /**
     * @brief Get the computed SHA-256 hash as hex string
     * @return Hexadecimal hash string (64 characters)
     *
     * Only valid after sendFile() returns true.
     */
    const std::string& getSha256Hash() const { return m_sha256HashString; }

    /**
     * @brief Get the raw SHA-256 hash
     * @return Pointer to 32-byte hash array
     *
     * Only valid after sendFile() returns true.
     */
    const unsigned char* getSha256HashRaw() const { return m_sha256Hash; }

    /**
     * @brief Check if hash has been computed
     * @return true if hash is valid
     */
    bool isHashComputed() const { return m_hashComputed; }

private:
    /**
     * @brief Initialize sender (validate file, get size)
     * @param errorMsg Output error message
     * @return true if successful
     */
    bool initialize(std::string& errorMsg);

    /**
     * @brief Send the OFFER header to receiver
     * @param socket TCP socket
     * @param errorMsg Output error message
     * @return true if successful
     */
    bool sendOfferHeader(TransportStream& stream, std::string& errorMsg);

    /**
     * @brief Wait for response header from receiver
     * @param socket TCP socket
     * @param response Output packet type
     * @param errorMsg Output error message
     * @return true if successful
     */
    bool waitForResponse(TransportStream& stream, PacketType& response, std::string& errorMsg);

    /**
     * @brief Stream file data over socket
     * @param socket TCP socket
     * @param errorMsg Output error message
     * @param progress Optional progress callback
     * @return true if successful
     */
    bool sendFileData(TransportStream& stream, std::string& errorMsg,
                      ProgressCallback progress);

    /**
     * @brief Update rolling SHA-256 hash
     * @param data Data to add to hash
     * @param size Size of data
     * @return true if successful
     */
    bool updateHash(const uint8_t* data, size_t size);

    // Member variables
    std::string m_filePath;              ///< Full path to source file
    std::string m_fileName;              ///< Just the filename
    std::string m_senderUuid;            ///< Sender device UUID (v0.2.0+)
    uint64_t m_fileSize;                 ///< File size in bytes
    unsigned char m_sha256Hash[HASH_SIZE];  ///< Computed SHA-256 hash
    std::string m_sha256HashString;      ///< Hash as hex string
    bool m_hashComputed;                 ///< Whether hash has been computed
    HashUtils::IncrementalHash m_incrementalHash;  ///< For computing hash during transfer
};

//=============================================================================
// FileReceiver Class
//=============================================================================

/**
 * @class FileReceiver
 * @brief Handles receiving files over a TCP socket
 *
 * This class manages the receiver side of file transfers:
 * 1. Receives OFFER header from sender
 * 2. Validates header (magic, filename, size)
 * 3. User decides to accept or reject
 * 4. If accepted, streams file data to disk in 64KB chunks
 * 5. Computes SHA-256 hash during transfer
 *
 * Usage:
 * @code
 * FileReceiver receiver("C:\\Downloads");
 * std::string error;
 * if (receiver.receiveFile(socket, error)) {
 *     std::cout << "File received: " << receiver.getReceivedFileName() << "\n";
 * }
 * @endcode
 */
class FileReceiver {
public:
    /**
     * @brief Constructor
     * @param downloadDir Directory where files will be saved
     *
     * The directory must exist and be writable.
     */
    explicit FileReceiver(const std::string& downloadDir);

    /**
     * @brief Destructor
     */
    ~FileReceiver();

    // Prevent copying
    FileReceiver(const FileReceiver&) = delete;
    FileReceiver& operator=(const FileReceiver&) = delete;

    // Allow moving
    FileReceiver(FileReceiver&&) noexcept;
    FileReceiver& operator=(FileReceiver&&) noexcept;

    /**
     * @brief Receive file from a connected TCP socket
     * @param socket Connected TCP socket
     * @param errorMsg Output error message if transfer fails
     * @param acceptCallback Callback to decide whether to accept transfer
     *                       Return true to accept, false to reject
     * @param progress Optional progress callback (can be nullptr)
     * @return true if transfer successful, false otherwise
     *
     * This method performs the complete receive operation:
     * 1. Receives OFFER header with file metadata
     * 2. Validates header (magic, filename size)
     * 3. Calls acceptCallback to let user decide
     * 4. Sends ACCEPT or REJECT header
     * 5. If accepted, streams file to disk in 64KB chunks
     * 6. Computes SHA-256 hash during transfer
     * 7. On error, deletes partial file
     */
    bool receiveFile(SOCKET socket,
                     std::string& errorMsg,
                     std::function<bool(const ExoHeader&)> acceptCallback,
                     ProgressCallback progress = nullptr);

    /**
     * @brief Receive file from a connected transport (plain TCP or TLS)
     */
    bool receiveFile(TransportStream& stream,
                     std::string& errorMsg,
                     std::function<bool(const ExoHeader&)> acceptCallback,
                     ProgressCallback progress = nullptr);

    /**
     * @brief Receive file from a connected TCP socket (with pre-received header)
     * @param socket Connected TCP socket
     * @param preReceivedHeader Already-received OFFER header from peer
     * @param errorMsg Output error message if transfer fails
     * @param acceptCallback Callback to decide whether to accept transfer
     * @param progress Optional progress callback (can be nullptr)
     * @return true if transfer successful, false otherwise
     *
     * This variant is used when the OFFER header has already been received
     * (e.g., by TransferServer). It skips the header receive step and proceeds
     * directly to the accept/reject decision and file data reception.
     */
    bool receiveFile(SOCKET socket,
                     const ExoHeader& preReceivedHeader,
                     std::string& errorMsg,
                     std::function<bool(const ExoHeader&)> acceptCallback,
                     ProgressCallback progress = nullptr);

    /**
     * @brief Receive file from a connected transport (plain TCP or TLS), with pre-received header
     */
    bool receiveFile(TransportStream& stream,
                     const ExoHeader& preReceivedHeader,
                     std::string& errorMsg,
                     std::function<bool(const ExoHeader&)> acceptCallback,
                     ProgressCallback progress = nullptr);

    /**
     * @brief Get the download directory
     * @return Directory path
     */
    const std::string& getDownloadDir() const { return m_downloadDir; }

    /**
     * @brief Get the full path to the received file
     * @return File path (only valid after successful receive)
     */
    const std::string& getReceivedFilePath() const { return m_outputPath; }

    /**
     * @brief Get just the filename (without path)
     * @return Filename
     */
    const std::string& getReceivedFileName() const { return m_fileName; }

    /**
     * @brief Get the number of bytes received
     * @return Bytes received
     */
    uint64_t getReceivedFileSize() const { return m_bytesReceived; }

    /**
     * @brief Get the computed SHA-256 hash as hex string
     * @return Hexadecimal hash string (64 characters)
     *
     * Only valid after receiveFile() returns true.
     */
    const std::string& getSha256Hash() const { return m_sha256HashString; }

    /**
     * @brief Get the raw SHA-256 hash
     * @return Pointer to 32-byte hash array
     *
     * Only valid after receiveFile() returns true.
     */
    const unsigned char* getSha256HashRaw() const { return m_sha256Hash; }

    /**
     * @brief Check if hash has been computed
     * @return true if hash is valid
     */
    bool isHashComputed() const { return m_hashComputed; }

    /**
     * @brief Check if there was a file size mismatch
     * @return true if received size != expected size
     */
    bool hasSizeMismatch() const { return m_sizeMismatch; }

private:
    /**
     * @brief Receive the OFFER header from sender
     * @param socket TCP socket
     * @param header Output header structure
     * @param errorMsg Output error message
     * @return true if successful
     */
    bool receiveOfferHeader(TransportStream& stream, ExoHeader& header, std::string& errorMsg);

    /**
     * @brief Send response header to sender
     * @param socket TCP socket
     * @param responseType ACCEPT, REJECT, or BUSY
     * @param errorMsg Output error message
     * @return true if successful
     */
    bool sendResponse(TransportStream& stream, PacketType responseType, std::string& errorMsg);

    /**
     * @brief Receive file data from socket and write to disk
     * @param socket TCP socket
     * @param header Header with expected file size and name
     * @param errorMsg Output error message
     * @param progress Optional progress callback
     * @return true if successful
     */
    bool receiveFileData(TransportStream& stream, const ExoHeader& header,
                         std::string& errorMsg, ProgressCallback progress);

    /**
     * @brief Sanitize filename by removing dangerous components
     * @param filename Filename to sanitize
     * @return true if filename is safe
     *
     * Strips path separators and relative path indicators.
     */
    bool sanitizeFilename(std::string& filename);

    /**
     * @brief Generate unique filename if file already exists
     * @param directory Directory to check
     * @param filename Original filename (will be modified)
     * @return Full path to unique filename
     */
    std::string generateUniqueFilename(const std::string& directory,
                                       std::string& filename);

    /**
     * @brief Delete the partially received file
     * @return true if deleted or didn't exist
     */
    bool deletePartialFile();

    /**
     * @brief Update rolling SHA-256 hash
     * @param data Data to add to hash
     * @param size Size of data
     * @return true if successful
     */
    bool updateHash(const uint8_t* data, size_t size);

    /**
     * @brief Check if there's enough disk space
     * @param requiredBytes Required space in bytes
     * @param directory Directory to check
     * @return true if enough space
     */
    bool hasEnoughDiskSpace(uint64_t requiredBytes, const std::string& directory);

    /**
     * @brief Validate download path for security
     * @param directory Directory path to validate
     * @return true if path is safe
     *
     * Checks for path traversal attempts and verifies directory exists.
     */
    bool validateDownloadPath(const std::string& directory);

    // Member variables
    std::string m_downloadDir;           ///< Destination directory
    std::string m_outputPath;            ///< Full path to output file
    std::string m_tempOutputPath;        ///< Temp path used during atomic write
    std::string m_fileName;              ///< Just the filename
#ifdef _WIN32
    ScopedWinFile m_outputHandle;        ///< Output file handle (Win32)
#else
    std::ofstream m_outputFile;          ///< Output file stream
#endif
    uint64_t m_bytesReceived;            ///< Bytes received counter
    unsigned char m_sha256Hash[HASH_SIZE];  ///< Computed SHA-256 hash
    std::string m_sha256HashString;      ///< Hash as hex string
    bool m_hashComputed;                 ///< Whether hash has been computed
    bool m_fileCreated;                  ///< Whether output file was created
    bool m_sizeMismatch;                 ///< Whether size didn't match header
    HashUtils::IncrementalHash m_incrementalHash;  ///< For computing hash during transfer
};

//=============================================================================
// Utility Functions
//=============================================================================

/**
 * @brief Send exactly N bytes over socket (handles partial sends)
 * @param socket TCP socket
 * @param data Data to send
 * @param size Number of bytes to send
 * @param errorMsg Output error message
 * @return true if all bytes sent successfully
 *
 * This loops until all bytes are sent or an error occurs.
 * TCP may send fewer bytes than requested, so we need to retry.
 */
bool sendExact(SOCKET socket, const uint8_t* data, size_t size,
                std::string& errorMsg);

/**
 * @brief Receive exactly N bytes from socket (handles partial receives)
 * @param socket TCP socket
 * @param buffer Buffer to receive data
 * @param size Number of bytes to receive
 * @param errorMsg Output error message
 * @return true if all bytes received successfully
 *
 * This loops until all bytes are received or connection closes.
 */
bool recvExact(SOCKET socket, uint8_t* buffer, size_t size,
                std::string& errorMsg);

/**
 * @brief Set socket receive timeout
 * @param socket Socket to configure
 * @param timeoutMs Timeout in milliseconds
 * @return true if successful
 *
 * Sets SO_RCVTIMEO socket option to cause recv() operations to timeout
 * after the specified number of milliseconds instead of blocking indefinitely.
 */
bool setSocketRecvTimeout(SOCKET socket, uint32_t timeoutMs);

//=============================================================================
// Phase 5: TLS Utility Functions
//=============================================================================

/**
 * @brief Send exactly N bytes over TLS connection (handles partial sends)
 * @param tls TlsSocket wrapper
 * @param data Data to send
 * @param size Number of bytes to send
 * @param errorMsg Output error message
 * @return true if all bytes sent successfully
 *
 * Phase 5: TLS-protected variant of sendExact().
 * Uses TlsSocket::sendExact() internally.
 */
bool sendExact(TlsSocket& tls, const uint8_t* data, size_t size,
                std::string& errorMsg);

/**
 * @brief Receive exactly N bytes from TLS connection (handles partial receives)
 * @param tls TlsSocket wrapper
 * @param buffer Buffer to receive data
 * @param size Number of bytes to receive
 * @param errorMsg Output error message
 * @return true if all bytes received successfully
 *
 * Phase 5: TLS-protected variant of recvExact().
 * Uses TlsSocket::recvExact() internally.
 */
bool recvExact(TlsSocket& tls, uint8_t* buffer, size_t size,
                std::string& errorMsg);

}  // namespace ExoSend
