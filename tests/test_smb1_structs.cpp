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

static_assert(sizeof(Smb1SessionSetupAndXRequest) == 27, "must be 27");
static_assert(sizeof(Smb1TreeConnectAndXRequest) == 9, "must be 9");
static_assert(sizeof(Smb1TreeConnectAndXResponse) == 7, "must be 7");
static_assert(sizeof(Smb1NtCreateAndXResponse) == 69, "must be 69");
static_assert(sizeof(Smb1ReadAndXResponse) == 25, "must be 25");
static_assert(sizeof(Smb1ReadAndXRequest) == 25, "must be 25");
static_assert(sizeof(Smb1WriteAndXRequest) == 29, "must be 29");
static_assert(sizeof(Smb1WriteAndXResponse) == 13, "must be 13");
static_assert(sizeof(Smb1CloseRequest) == 7, "must be 7");
static_assert(sizeof(Smb1TransactionRequest) == 29, "must be 29");
static_assert(sizeof(Smb1Transaction2Request) == 29, "must be 29");
static_assert(sizeof(Smb1NtTransactRequest) == 39, "must be 39");
static_assert(sizeof(Smb1EchoRequest) == 3, "must be 3");
static_assert(sizeof(Smb1LogoffAndXRequest) == 5, "must be 5");
static_assert(sizeof(Smb1LockingAndXRequest) == 17, "must be 17");
static_assert(sizeof(Smb1OpenAndXResponse) == 30, "must be 30");
static_assert(sizeof(Smb1QueryInformationResponse) == 21, "must be 21");
static_assert(sizeof(Smb1SetInformationRequest) == 17, "must be 17");
static_assert(sizeof(Smb1DeleteRequest) == 3, "must be 3");
static_assert(sizeof(Smb1RenameRequest) == 3, "must be 3");
static_assert(sizeof(Smb1FlushRequest) == 3, "must be 3");
static_assert(sizeof(Smb1IoctlRequest) == 11, "must be 11");
static_assert(sizeof(Smb1QueryInformation2Request) == 3, "must be 3");
static_assert(sizeof(Smb1SetInformation2Request) == 15, "must be 15");
static_assert(sizeof(Smb1WriteAndCloseRequest) == 25, "must be 25");
static_assert(sizeof(Smb1ReadRawRequest) == 17, "must be 17");
static_assert(sizeof(Smb1WriteRawRequest) == 25, "must be 25");
static_assert(sizeof(Smb1ReadMpxRequest) == 17, "must be 17");
static_assert(sizeof(Smb1WriteMpxRequest) == 25, "must be 25");

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
