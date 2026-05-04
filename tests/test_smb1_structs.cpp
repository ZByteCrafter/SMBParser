#include <gtest/gtest.h>
#include <smbparser/smb1_structs.h>
#include <smbparser/types.h>

using namespace smbparser;

// Size validation
static_assert(sizeof(Smb1Header) == 32, "Smb1Header must be 32 bytes");
static_assert(sizeof(Smb1NegotiateResponse) == 35, "Smb1NegotiateResponse must be 35 bytes");

TEST(Smb1StructsTest, HeaderSize) {
    EXPECT_EQ(sizeof(Smb1Header), 32u);
}

TEST(Smb1StructsTest, HeaderOffsets) {
    Smb1Header hdr{};
    uint8_t* base = reinterpret_cast<uint8_t*>(&hdr);
    // command at offset 4
    EXPECT_EQ(&hdr.command - base, 4);
    // status at offset 5
    EXPECT_EQ(reinterpret_cast<uint8_t*>(&hdr.status) - base, 5);
    // flags at offset 9
    EXPECT_EQ(&hdr.flags - base, 9);
    // tid at offset 24
    EXPECT_EQ(reinterpret_cast<uint8_t*>(&hdr.tid) - base, 24);
    // uid at offset 28
    EXPECT_EQ(reinterpret_cast<uint8_t*>(&hdr.uid) - base, 28);
    // mid at offset 30
    EXPECT_EQ(reinterpret_cast<uint8_t*>(&hdr.mid) - base, 30);
}

TEST(Smb1StructsTest, NegotiateResponseSize) {
    EXPECT_EQ(sizeof(Smb1NegotiateResponse), 35u);
}

TEST(Smb1StructsTest, NegotiateResponseFieldValues) {
    uint8_t raw[] = {
        0x11,                      // WordCount = 17
        0x05, 0x00,                // dialect_index = 5 (LE)
        0x03,                      // security_mode
        0x0A, 0x00,                // max_mpx_count = 10
        0x01, 0x00,                // max_vc_count = 1
        0x00, 0x10, 0x00, 0x00,    // max_buffer_size = 4096
        0x00, 0x10, 0x00, 0x00,    // max_raw_size = 4096
        0xEF, 0xBE, 0xAD, 0xDE,    // session_key
        0xD3, 0x00, 0x00, 0x00,    // capabilities = 0xD3
        0x78, 0x56, 0x34, 0x12,    // system_time_low
        0xBC, 0x9A, 0x78, 0x56,    // system_time_high
        0xE4, 0xFF,                // server_timezone = -28
        0x08,                      // challenge_len = 8
    };
    const Smb1NegotiateResponse* resp = reinterpret_cast<const Smb1NegotiateResponse*>(raw);
    EXPECT_EQ(resp->word_count, 0x11);
    EXPECT_EQ(le16toh(resp->dialect_index), 5);
    EXPECT_EQ(resp->security_mode, 3);
    EXPECT_EQ(le32toh(resp->max_buffer_size), 4096u);
    EXPECT_EQ(le32toh(resp->capabilities), 0xD3u);
}
