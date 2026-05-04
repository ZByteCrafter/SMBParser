#include <gtest/gtest.h>
#include <smbparser/smb2_structs.h>
#include <smbparser/smb2_packet.h>
#include <smbparser/types.h>
#include <vector>
#include <cstring>

using namespace smbparser;

static_assert(sizeof(Smb2Header) == 64, "Smb2Header must be 64 bytes");
static_assert(sizeof(Smb2NegotiateResponse) == 64, "Smb2NegotiateResponse must be 64 bytes");
static_assert(sizeof(Smb2CreateResponse) == 89, "must be 89");
static_assert(sizeof(Smb2ReadResponse) == 17, "must be 17");
static_assert(sizeof(Smb2CloseResponse) == 60, "must be 60");

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
