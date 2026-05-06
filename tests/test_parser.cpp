#include <gtest/gtest.h>
#include <smbparser/smb_parser.h>
#include <smbparser/smb1_structs.h>
#include <smbparser/smb2_structs.h>
#include <smbparser/types.h>
#include <vector>

using namespace smbparser;

static std::vector<uint8_t> makeNetbiosV1() {
    std::vector<uint8_t> inner;
    inner.push_back(0xFF); inner.push_back('S'); inner.push_back('M'); inner.push_back('B');
    inner.push_back(SMB_COM_NEGOTIATE);
    for (int i = 0; i < 27; i++) inner.push_back(0x00);
    inner.push_back(0x00);
    inner.push_back(0x00); inner.push_back(0x00);

    uint32_t nb_len = static_cast<uint32_t>(inner.size());
    std::vector<uint8_t> out;
    out.push_back(0x00);
    out.push_back((nb_len >> 16) & 0xFF);
    out.push_back((nb_len >> 8) & 0xFF);
    out.push_back(nb_len & 0xFF);
    out.insert(out.end(), inner.begin(), inner.end());
    return out;
}

static std::vector<uint8_t> makeDirectTcpV2() {
    std::vector<uint8_t> buf(128, 0);
    auto* hdr = reinterpret_cast<Smb2Header*>(buf.data());
    hdr->protocol[0] = 0xFE; hdr->protocol[1] = 'S'; hdr->protocol[2] = 'M'; hdr->protocol[3] = 'B';
    hdr->structure_size = 64;
    return buf;
}

TEST(SMBParserTest, DetectNetBIOSTransport) {
    SMBParser parser;
    auto buf = makeNetbiosV1();
    parser.feed(buf.data(), buf.size());
    EXPECT_EQ(parser.transport(), Transport::NetBIOS);
    EXPECT_EQ(parser.messageCount(), 1u);
}

TEST(SMBParserTest, DetectDirectTCPTransport) {
    SMBParser parser;
    auto buf = makeDirectTcpV2();
    parser.feed(buf.data(), buf.size());
    EXPECT_EQ(parser.transport(), Transport::DirectTCP);
    EXPECT_GT(parser.messageCount(), 0u);
}

TEST(SMBParserTest, FeedSegmentedData) {
    SMBParser parser;
    auto full = makeNetbiosV1();
    size_t c1 = parser.feed(full.data(), 4);
    EXPECT_EQ(parser.messageCount(), 0u);
    size_t c2 = parser.feed(full.data() + 4, full.size() - 4);
    EXPECT_EQ(parser.messageCount(), 1u);
}

TEST(SMBParserTest, ToJsonReturnsArray) {
    SMBParser parser;
    parser.feed(makeNetbiosV1().data(), makeNetbiosV1().size());
    auto j = parser.toJson();
    EXPECT_TRUE(j.is_array());
    EXPECT_EQ(j.size(), 1u);
}

TEST(SMBParserTest, ToJsonLinesFormat) {
    SMBParser parser;
    parser.feed(makeNetbiosV1().data(), makeNetbiosV1().size());
    std::string lines = parser.toJsonLines();
    EXPECT_FALSE(lines.empty());
    EXPECT_NE(lines.find("SMBv1"), std::string::npos);
}

TEST(SMBParserTest, ErrorRecoverySkipsCorruptData) {
    SMBParser parser;
    auto buf = makeNetbiosV1();
    std::vector<uint8_t> corrupt = {0xAA, 0xBB, 0xCC};
    corrupt.insert(corrupt.end(), buf.begin(), buf.end());
    parser.feed(corrupt.data(), corrupt.size());
    EXPECT_GT(parser.errorCount(), 0u);
    EXPECT_EQ(parser.messageCount(), 1u);
}

TEST(SMBParserTest, DirectTcpV1ExactMessageSize) {
    // Build two consecutive SMBv1 messages in a single DirectTCP stream
    auto makeV1Negotiate = []() {
        std::vector<uint8_t> buf;
        buf.push_back(0xFF); buf.push_back('S'); buf.push_back('M'); buf.push_back('B');
        buf.push_back(SMB_COM_NEGOTIATE);
        for (int i = 0; i < 27; i++) buf.push_back(0x00);
        buf.push_back(0x00);
        buf.push_back(0x00); buf.push_back(0x00);
        return buf;
    };

    auto msg1 = makeV1Negotiate();
    auto msg2 = makeV1Negotiate();
    std::vector<uint8_t> stream;
    stream.insert(stream.end(), msg1.begin(), msg1.end());
    stream.insert(stream.end(), msg2.begin(), msg2.end());

    SMBParser parser;
    parser.feed(stream.data(), stream.size());
    EXPECT_EQ(parser.messageCount(), 2u);
    // First message should have exact size, not entire stream size
    const SMBv1Packet* pkt1 = parser.getV1Message(0);
    ASSERT_NE(pkt1, nullptr);
    EXPECT_TRUE(pkt1->isValid());
    // Check that dataBlockSize reflects ByteCount=0 (not inflated)
    EXPECT_EQ(pkt1->dataBlockSize(), 0u);
}

TEST(SMBParserTest, DirectTcpV2CompoundExactStorage) {
    // Build two independent SMBv2 messages in DirectTCP mode
    auto makeV2Negotiate = []() {
        std::vector<uint8_t> buf(128, 0);
        auto* hdr = reinterpret_cast<Smb2Header*>(buf.data());
        hdr->protocol[0] = 0xFE; hdr->protocol[1] = 'S';
        hdr->protocol[2] = 'M'; hdr->protocol[3] = 'B';
        hdr->structure_size = 64;
        hdr->command = SMB2_NEGOTIATE;
        return buf;
    };

    auto msg1 = makeV2Negotiate();
    auto msg2 = makeV2Negotiate();
    std::vector<uint8_t> stream;
    stream.insert(stream.end(), msg1.begin(), msg1.end());
    stream.insert(stream.end(), msg2.begin(), msg2.end());

    SMBParser parser;
    parser.feed(stream.data(), stream.size());
    EXPECT_EQ(parser.messageCount(), 2u);
    // Each packet should see its own data, not the entire stream
    const SMBv2Packet* pkt1 = parser.getV2Message(0);
    ASSERT_NE(pkt1, nullptr);
    // commandParamsSize should be 128-64=64, not inflated with second message
    EXPECT_EQ(pkt1->commandParamsSize(), 64u);
}

TEST(SMBParserTest, NetBIOSDetectionRequiresFullMagic) {
    // Construct a stream that starts with 0x00 + 3-byte length + only one byte 0xFF
    // but NOT full \xFFSMB magic — should NOT be detected as NetBIOS
    std::vector<uint8_t> fake_nb = {
        0x00,                   // NBSS type
        0x00, 0x00, 0x20,      // length = 32
        0xFF, 0x00, 0x00, 0x00, // NOT \xFFSMB — just 0xFF followed by zeros
    };
    fake_nb.resize(36, 0x00);

    SMBParser parser;
    parser.feed(fake_nb.data(), fake_nb.size());
    // Should NOT detect as NetBIOS because full magic is not present
    EXPECT_NE(parser.transport(), Transport::NetBIOS);
}
