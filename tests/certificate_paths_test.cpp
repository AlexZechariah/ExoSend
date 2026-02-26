#include <gtest/gtest.h>

#include "exosend/CertificateManager.h"

#include <string>

static bool endsWith(const std::string& s, const std::string& suffix)
{
    if (s.size() < suffix.size()) {
        return false;
    }
    return s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

TEST(CertificatePathsTest, DefaultCertDirIsUnderLocalAppData)
{
#ifdef _WIN32
    const std::string dir = ExoSend::CertificateManager::getDefaultCertDir();
    ASSERT_FALSE(dir.empty());

    // getDefaultCertDir normalizes to forward slashes.
    EXPECT_TRUE(endsWith(dir, "/ExoSend/certs")) << dir;
    EXPECT_EQ(dir.find("/AppData/Roaming/"), std::string::npos) << dir;
#else
    GTEST_SKIP() << "Windows-only default cert dir contract";
#endif
}

