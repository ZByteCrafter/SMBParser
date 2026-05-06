#include <gtest/gtest.h>
#include <smbparser/smb2_structs.h>
#include <smbparser/smb2_packet.h>
#include <smbparser/types.h>
#include <vector>
#include <cstring>

using namespace smbparser;

static_assert(sizeof(Smb2Header) == 64, "Smb2Header must be 64 bytes");
static_assert(sizeof(Smb2NegotiateResponse) == 64, "Smb2NegotiateResponse must be 64 bytes");
static_assert(sizeof(Smb2NegotiateRequest) == 36, "must be 36");
static_assert(sizeof(Smb2CreateResponse) == 89, "must be 89");
static_assert(sizeof(Smb2CreateRequest) == 56, "must be 56");
static_assert(sizeof(Smb2ReadRequest) == 48, "must be 48");
static_assert(sizeof(Smb2ReadResponse) == 17, "must be 17");
static_assert(sizeof(Smb2WriteRequest) == 48, "must be 48");
static_assert(sizeof(Smb2WriteResponse) == 16, "must be 16");
static_assert(sizeof(Smb2CloseRequest) == 24, "must be 24");
static_assert(sizeof(Smb2CloseResponse) == 60, "must be 60");
static_assert(sizeof(Smb2SessionSetupRequest) == 24, "must be 24");
static_assert(sizeof(Smb2SessionSetupResponse) == 8, "must be 8");
static_assert(sizeof(Smb2TreeConnectRequest) == 8, "must be 8");
static_assert(sizeof(Smb2TreeConnectResponse) == 16, "must be 16");
static_assert(sizeof(Smb2FlushRequest) == 24, "must be 24");
static_assert(sizeof(Smb2FlushResponse) == 4, "must be 4");
static_assert(sizeof(Smb2LockRequest) == 24, "must be 24");
static_assert(sizeof(Smb2LockResponse) == 4, "must be 4");
static_assert(sizeof(Smb2IoctlRequest) == 56, "must be 56");
static_assert(sizeof(Smb2IoctlResponse) == 48, "must be 48");

static std::vector<uint8_t> makeSmb2NegotiateResponse() {
    std::vector<uint8_t> buf(128, 0);
    auto* hdr = reinterpret_cast<Smb2Header*>(buf.data());
    hdr->protocol[0] = 0xFE; hdr->protocol[1] = 'S'; hdr->protocol[2] = 'M'; hdr->protocol[3] = 'B';
    hdr->structure_size = 64;
    hdr->command = 0x0000;
    return buf;
}

TEST(SMBv2PacketTest, ValidPacket) {
    auto buf = makeSmb2NegotiateResponse();
    SMBv2Packet pkt(buf.data(), buf.size());
    EXPECT_TRUE(pkt.isValid());
    EXPECT_NE(pkt.header(), nullptr);
    EXPECT_EQ(pkt.command(), 0x0000u);
}

TEST(SMBv2PacketTest, TooShort) {
    uint8_t buf[10] = {};
    SMBv2Packet pkt(buf, sizeof(buf));
    EXPECT_FALSE(pkt.isValid());
}

TEST(SMBv2PacketTest, BadMagic) {
    auto buf = makeSmb2NegotiateResponse();
    buf[0] = 0x00;
    SMBv2Packet pkt(buf.data(), buf.size());
    EXPECT_FALSE(pkt.isValid());
}

TEST(SMBv2PacketTest, ToJsonValid) {
    auto buf = makeSmb2NegotiateResponse();
    SMBv2Packet pkt(buf.data(), buf.size());
    auto j = pkt.toJson();
    EXPECT_EQ(j["protocol"], "SMBv2");
    EXPECT_EQ(j["command"], "SMB2_NEGOTIATE");
    EXPECT_EQ(j["valid"], true);
    EXPECT_EQ(j["has_next"], false);
}

TEST(SMBv2PacketTest, HeaderFields) {
    auto buf = makeSmb2NegotiateResponse();
    auto* hdr = reinterpret_cast<Smb2Header*>(buf.data());
    hdr->message_id = 42;
    hdr->tree_id = 1;
    hdr->session_id = 0xDEADBEEF;
    SMBv2Packet pkt(buf.data(), buf.size());
    EXPECT_EQ(pkt.messageId(), 42u);
    EXPECT_EQ(pkt.treeId(), 1u);
    EXPECT_EQ(pkt.sessionId(), 0xDEADBEEFu);
}

TEST(SMBv2PacketTest, ToJsonNegotiateHasParams) {
    auto buf = makeSmb2NegotiateResponse();
    auto* resp = reinterpret_cast<Smb2NegotiateResponse*>(buf.data() + 64);
    resp->structure_size = 65;
    resp->dialect_revision = SMB2_DIALECT_210;
    SMBv2Packet pkt(buf.data(), buf.size());
    auto j = pkt.toJson();
    EXPECT_TRUE(j.contains("params"));
    EXPECT_TRUE(j["params"].contains("dialect_revision"));
}

TEST(SMBv2PacketTest, ToJsonWriteResponse) {
    // Build a WRITE response packet
    std::vector<uint8_t> buf(64 + sizeof(Smb2WriteResponse), 0);
    auto* h = reinterpret_cast<Smb2Header*>(buf.data());
    h->protocol[0] = 0xFE; h->protocol[1] = 'S'; h->protocol[2] = 'M'; h->protocol[3] = 'B';
    h->structure_size = 64;
    h->command = SMB2_WRITE;
    auto* wr = reinterpret_cast<Smb2WriteResponse*>(buf.data() + 64);
    wr->structure_size = 17;
    wr->count = 512;
    wr->remaining = 0;

    SMBv2Packet pkt(buf.data(), buf.size());
    EXPECT_TRUE(pkt.isValid());
    auto j = pkt.toJson();
    EXPECT_EQ(j["command"], "SMB2_WRITE");
    // WRITE response should have params with count
    EXPECT_TRUE(j.contains("params"));
    EXPECT_TRUE(j["params"].contains("count"));
    EXPECT_EQ(j["params"]["count"], 512u);
}
