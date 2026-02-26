#include <gtest/gtest.h>

#include "exosend/WindowsFilename.h"

TEST(WindowsFilename, RejectsAlternateDataStream) {
    std::string name = "report.pdf:evil.exe";
    EXPECT_FALSE(ExoSend::sanitizeWindowsFilenameInPlace(name));
}

TEST(WindowsFilename, RejectsReservedDeviceNames) {
    std::string a = "CON";
    std::string b = "nul.txt";
    std::string c = "LPT1.tar.gz";
    EXPECT_FALSE(ExoSend::sanitizeWindowsFilenameInPlace(a));
    EXPECT_FALSE(ExoSend::sanitizeWindowsFilenameInPlace(b));
    EXPECT_FALSE(ExoSend::sanitizeWindowsFilenameInPlace(c));
}

TEST(WindowsFilename, RejectsControlCharacters) {
    std::string name;
    name.push_back('a');
    name.push_back('\x1F');
    name.push_back('b');
    EXPECT_FALSE(ExoSend::sanitizeWindowsFilenameInPlace(name));
}

TEST(WindowsFilename, ReplacesInvalidCharacters) {
    std::string name = "a<b>c|d?e*f\"g.txt";
    EXPECT_TRUE(ExoSend::sanitizeWindowsFilenameInPlace(name));
    EXPECT_EQ(name, "a_b_c_d_e_f_g.txt");
}

TEST(WindowsFilename, TrimsTrailingDotsAndSpaces) {
    std::string name = "invoice.pdf.  ";
    EXPECT_TRUE(ExoSend::sanitizeWindowsFilenameInPlace(name));
    EXPECT_EQ(name, "invoice.pdf");
}

TEST(WindowsFilename, EnforcesMaxLength) {
    std::string name(241, 'a');
    EXPECT_FALSE(ExoSend::sanitizeWindowsFilenameInPlace(name));
}

TEST(WindowsFilename, IsSafeReturnsTrueForAlreadySafeNames) {
    EXPECT_TRUE(ExoSend::isSafeWindowsFilename("invoice.pdf"));
    EXPECT_FALSE(ExoSend::isSafeWindowsFilename("invoice.pdf. "));
}

