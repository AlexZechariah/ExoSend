/**
 * @file TransportStream.h
 * @brief Minimal transport abstraction for plain sockets and TLS sockets
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <winsock2.h>

namespace ExoSend {

class TlsSocket;

/**
 * @brief Minimal stream interface used by the transfer protocol.
 *
 * The file transfer protocol requires exact-length reads and writes for both
 * fixed-size frames (headers) and streaming chunks. This interface abstracts
 * the underlying transport (plain TCP or TLS) while keeping the hot path simple.
 */
class TransportStream {
public:
    virtual ~TransportStream() = default;
    virtual bool sendExact(const uint8_t* data, size_t size, std::string& errorMsg) = 0;
    virtual bool recvExact(uint8_t* buffer, size_t size, std::string& errorMsg) = 0;
    virtual void shutdown() {}
    virtual bool isTls() const { return false; }
    virtual std::string getPeerFingerprint(std::string& errorMsg) {
        (void)errorMsg;
        return {};
    }
};

class PlainSocketStream final : public TransportStream {
public:
    explicit PlainSocketStream(SOCKET socket) : m_socket(socket) {}

    bool sendExact(const uint8_t* data, size_t size, std::string& errorMsg) override;
    bool recvExact(uint8_t* buffer, size_t size, std::string& errorMsg) override;

private:
    SOCKET m_socket;
};

class TlsTransportStream final : public TransportStream {
public:
    explicit TlsTransportStream(TlsSocket& tls) : m_tls(tls) {}

    bool sendExact(const uint8_t* data, size_t size, std::string& errorMsg) override;
    bool recvExact(uint8_t* buffer, size_t size, std::string& errorMsg) override;
    void shutdown() override;
    bool isTls() const override { return true; }
    std::string getPeerFingerprint(std::string& errorMsg) override;

private:
    TlsSocket& m_tls;
};

}  // namespace ExoSend

