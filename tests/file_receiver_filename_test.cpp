#include <gtest/gtest.h>

#include "exosend/FileTransfer.h"
#include "exosend/TransportStream.h"

namespace {

class DummyStream final : public ExoSend::TransportStream {
public:
    bool sendExact(const uint8_t* data, size_t size, std::string& errorMsg) override {
        (void)data;
        (void)size;
        errorMsg = "DummyStream::sendExact should not be called";
        return false;
    }

    bool recvExact(uint8_t* buffer, size_t size, std::string& errorMsg) override {
        (void)buffer;
        (void)size;
        errorMsg = "DummyStream::recvExact should not be called";
        return false;
    }
};

}  // namespace

TEST(FileReceiverFilename, RejectsAdsSpecifierInOfferFilename) {
    ExoSend::FileReceiver receiver("C:\\");
    DummyStream stream;

    ExoSend::ExoHeader offer(ExoSend::PacketType::OFFER, 0, "report.pdf:evil.exe");
    std::string error;

    const bool ok = receiver.receiveFile(
        stream,
        offer,
        error,
        [](const ExoSend::ExoHeader&) { return false; },
        nullptr
    );

    EXPECT_FALSE(ok);
    EXPECT_EQ(error, "Invalid filename received");
}

TEST(FileReceiverFilename, RejectsReservedDeviceNameInOfferFilename) {
    ExoSend::FileReceiver receiver("C:\\");
    DummyStream stream;

    ExoSend::ExoHeader offer(ExoSend::PacketType::OFFER, 0, "CON.txt");
    std::string error;

    const bool ok = receiver.receiveFile(
        stream,
        offer,
        error,
        [](const ExoSend::ExoHeader&) { return false; },
        nullptr
    );

    EXPECT_FALSE(ok);
    EXPECT_EQ(error, "Invalid filename received");
}

