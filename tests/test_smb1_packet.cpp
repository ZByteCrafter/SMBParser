#include <gtest/gtest.h>
#include <smbparser/smb1_packet.h>
#include <smbparser/smb1_structs.h>
#include <smbparser/types.h>
#include <vector>

using namespace smbparser;

// Helper: build a minimal valid SMBv1 NEGOTIATE response
static std::vector<uint8_t> makeNegotiateResponse() {
    std::vector<uint8_t> buf;
    // Smb1Header (32 bytes)
    buf.push_back(0xFF); buf.push_back('S'); buf.push_back('M'); buf.push_back('B');
    buf.push_back(SMB_COM_NEGOTIATE); // command
    // status (4 bytes LE) = STATUS_SUCCESS
    buf.push_back(0x00); buf.push_back(0x00); buf.push_back(0x00); buf.push_back(0x00);
    // flags, flags2 (2 bytes)
    buf.push_back(0x00); buf.push_back(0x00); buf.push_back(0x00);
    // pid_high (2 bytes)
    buf.push_back(0x00); buf.push_back(0x00);
    // signature[8]
    for (int i = 0; i < 8; i++) buf.push_back(0x00);
    // reserved (2 bytes)
    buf.push_back(0x00); buf.push_back(0x00);
    // tid (2 bytes)
    buf.push_back(0x01); buf.push_back(0x00);
    // pid_low (2 bytes)
    buf.push_back(0x00); buf.push_back(0x00);
    // uid (2 bytes)
    buf.push_back(0x00); buf.push_back(0x00);
    // mid (2 bytes) = 1
    buf.push_back(0x01); buf.push_back(0x00);
    
    // WordCount = 17
    buf.push_back(0x11);
    // 17 words (34 bytes) of param block - fill with zeros
    for (int i = 0; i < 34; i++) buf.push_back(0x00);
    
    // ByteCount = 0
    buf.push_back(0x00); buf.push_back(0x00);
    
    return buf;
}

TEST(SMBv1PacketTest, ValidPacket) {
    auto buf = makeNegotiateResponse();
    SMBv1Packet pkt(buf.data(), buf.size());
    EXPECT_TRUE(pkt.isValid());
    EXPECT_TRUE(pkt.errorMessage().empty());
    EXPECT_NE(pkt.header(), nullptr);
    EXPECT_EQ(pkt.command(), SMB_COM_NEGOTIATE);
    EXPECT_EQ(pkt.status(), 0x00000000u);
}

TEST(SMBv1PacketTest, TooShort) {
    uint8_t buf[10] = {};
    SMBv1Packet pkt(buf, sizeof(buf));
    EXPECT_FALSE(pkt.isValid());
    EXPECT_FALSE(pkt.errorMessage().empty());
}

TEST(SMBv1PacketTest, BadMagic) {
    auto buf = makeNegotiateResponse();
    buf[0] = 0x00; // corrupt magic
    SMBv1Packet pkt(buf.data(), buf.size());
    EXPECT_FALSE(pkt.isValid());
    EXPECT_NE(pkt.errorMessage().find("magic"), std::string::npos);
}

TEST(SMBv1PacketTest, ToJsonValid) {
    auto buf = makeNegotiateResponse();
    SMBv1Packet pkt(buf.data(), buf.size());
    auto j = pkt.toJson();
    EXPECT_EQ(j["protocol"], "SMBv1");
    EXPECT_EQ(j["command"], "SMB_COM_NEGOTIATE");
    EXPECT_EQ(j["command_code"], SMB_COM_NEGOTIATE);
    EXPECT_EQ(j["valid"], true);
    EXPECT_EQ(j["flags"], 0);
    // Verify header fields are present
    EXPECT_TRUE(j.contains("tid"));
    EXPECT_TRUE(j.contains("uid"));
    EXPECT_TRUE(j.contains("mid"));
}

TEST(SMBv1PacketTest, ToJsonInvalid) {
    uint8_t buf[10] = {};
    SMBv1Packet pkt(buf, sizeof(buf));
    auto j = pkt.toJson();
    EXPECT_EQ(j["protocol"], "SMBv1");
    EXPECT_EQ(j["valid"], false);
    EXPECT_TRUE(j.contains("error"));
}

TEST(SMBv1PacketTest, DataBlockAccess) {
    auto buf = makeNegotiateResponse();
    SMBv1Packet pkt(buf.data(), buf.size());
    EXPECT_EQ(pkt.dataBlockSize(), 0u); // ByteCount=0
    EXPECT_NE(pkt.dataBlock(), nullptr);
    EXPECT_NE(pkt.paramBlock(), nullptr);
}

TEST(SMBv1PacketTest, ToJsonNegotiateHasParams) {
    auto buf = makeNegotiateResponse();
    // Fill negotiate response fields in param block
    // WordCount at offset 32
    // dialect_index at offset 33,34
    buf[32 + 1 + 0] = 0x05; // dialect_index low byte
    buf[32 + 1 + 2] = 0x03; // security_mode
    SMBv1Packet pkt(buf.data(), buf.size());
    auto j = pkt.toJson();
    EXPECT_TRUE(j.contains("params"));
    EXPECT_TRUE(j["params"].contains("dialect_index"));
}

TEST(SMBv1PacketTest, UnalignedByteCountRead) {
    // Build a packet with WordCount=1 (odd number of words),
    // so param_end = 32 + 1 + 1*2 = 35 (odd offset for ByteCount)
    std::vector<uint8_t> buf;
    // Smb1Header (32 bytes)
    buf.push_back(0xFF); buf.push_back('S'); buf.push_back('M'); buf.push_back('B');
    buf.push_back(SMB_COM_ECHO); // command
    buf.push_back(0x00); buf.push_back(0x00); buf.push_back(0x00); buf.push_back(0x00); // status
    buf.push_back(0x00); buf.push_back(0x00); buf.push_back(0x00); // flags, flags2
    buf.push_back(0x00); buf.push_back(0x00); // pid_high
    for (int i = 0; i < 8; i++) buf.push_back(0x00); // signature
    buf.push_back(0x00); buf.push_back(0x00); // reserved
    buf.push_back(0x01); buf.push_back(0x00); // tid
    buf.push_back(0x00); buf.push_back(0x00); // pid_low
    buf.push_back(0x00); buf.push_back(0x00); // uid
    buf.push_back(0x01); buf.push_back(0x00); // mid
    // WordCount = 1
    buf.push_back(0x01);
    // 1 word (2 bytes) = echo_count
    buf.push_back(0x03); buf.push_back(0x00);
    // ByteCount = 4 (at odd offset 35) — small enough to fit in buffer
    buf.push_back(0x04); buf.push_back(0x00);
    // 4 bytes of data
    buf.push_back(0xAA); buf.push_back(0xBB); buf.push_back(0xCC); buf.push_back(0xDD);

    SMBv1Packet pkt(buf.data(), buf.size());
    EXPECT_TRUE(pkt.isValid());
    EXPECT_EQ(pkt.dataBlockSize(), 4u);
}
