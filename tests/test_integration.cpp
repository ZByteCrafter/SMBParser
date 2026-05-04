#include <gtest/gtest.h>
#include <smbparser/smb_parser.h>
#include <smbparser/file_assembler.h>
#include <smbparser/smb2_structs.h>
#include <smbparser/smb2_packet.h>
#include <smbparser/types.h>
#include <vector>
#include <cstring>

using namespace smbparser;

static std::vector<uint8_t> buildFileTransferStream() {
    std::vector<uint8_t> stream;

    auto wrap = [&stream](const std::vector<uint8_t>& smb_data) {
        uint32_t len = static_cast<uint32_t>(smb_data.size());
        stream.push_back(0x00);
        stream.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        stream.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        stream.push_back(static_cast<uint8_t>(len & 0xFF));
        stream.insert(stream.end(), smb_data.begin(), smb_data.end());
    };

    auto makeSMB2 = [](uint16_t cmd, uint64_t msg_id, uint64_t sess_id, uint32_t tid, size_t param_size) {
        std::vector<uint8_t> buf(64 + param_size, 0);
        auto* h = reinterpret_cast<Smb2Header*>(buf.data());
        h->protocol[0] = 0xFE; h->protocol[1] = 'S'; h->protocol[2] = 'M'; h->protocol[3] = 'B';
        h->structure_size = 64;
        h->command = cmd;
        h->message_id = msg_id;
        h->session_id = sess_id;
        h->tree_id = tid;
        return buf;
    };

    uint64_t sess_id = 0x12345678ULL;
    uint32_t tid = 1;

    auto nego = makeSMB2(0x0000, 0, 0, 0, 64);
    auto* nr = reinterpret_cast<Smb2NegotiateResponse*>(nego.data() + 64);
    nr->structure_size = 65;
    nr->dialect_revision = SMB2_DIALECT_210;
    wrap(nego);

    auto sess = makeSMB2(0x0001, 1, sess_id, 0, 9);
    auto* sr = reinterpret_cast<Smb2SessionSetupResponse*>(sess.data() + 64);
    sr->structure_size = 9;
    sr->session_flags = 1;
    wrap(sess);

    auto tree = makeSMB2(0x0003, 2, sess_id, tid, 16);
    auto* tr = reinterpret_cast<Smb2TreeConnectResponse*>(tree.data() + 64);
    tr->structure_size = 16;
    tr->share_type = 1;
    wrap(tree);

    uint8_t fid_bytes[16] = {0xFF, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0};
    auto create = makeSMB2(0x0005, 3, sess_id, tid, 89);
    auto* cr = reinterpret_cast<Smb2CreateResponse*>(create.data() + 64);
    cr->structure_size = 89;
    cr->end_of_file = 12;
    memcpy(cr->file_id, fid_bytes, 16);
    wrap(create);

    std::string chunk1 = "HELLO";
    auto read1 = makeSMB2(0x0008, 4, sess_id, tid, 17 + chunk1.size());
    auto* rr1 = reinterpret_cast<Smb2ReadResponse*>(read1.data() + 64);
    rr1->structure_size = 17;
    rr1->data_offset = static_cast<uint8_t>(sizeof(Smb2Header) + sizeof(Smb2ReadResponse));
    rr1->data_length = static_cast<uint32_t>(chunk1.size());
    memcpy(read1.data() + 64 + 17, chunk1.data(), chunk1.size());
    wrap(read1);

    std::string chunk2 = "WORLD";
    auto read2 = makeSMB2(0x0008, 5, sess_id, tid, 17 + chunk2.size());
    auto* rr2 = reinterpret_cast<Smb2ReadResponse*>(read2.data() + 64);
    rr2->structure_size = 17;
    rr2->data_offset = static_cast<uint8_t>(sizeof(Smb2Header) + sizeof(Smb2ReadResponse));
    rr2->data_length = static_cast<uint32_t>(chunk2.size());
    memcpy(read2.data() + 64 + 17, chunk2.data(), chunk2.size());
    wrap(read2);

    auto close = makeSMB2(0x0006, 6, sess_id, tid, 60);
    auto* clr = reinterpret_cast<Smb2CloseResponse*>(close.data() + 64);
    clr->structure_size = 60;
    clr->end_of_file = 10;
    wrap(close);

    return stream;
}

TEST(IntegrationTest, FullPipelineFileTransfer) {
    auto stream = buildFileTransferStream();
    SMBParser parser;
    FileAssembler assembler;

    size_t mid = stream.size() / 3;
    size_t count1 = parser.feed(stream.data(), mid);
    size_t count2 = parser.feed(stream.data() + mid, stream.size() - mid);
    parser.flush();

    size_t total = parser.messageCount();
    EXPECT_EQ(total, 7u);
    EXPECT_EQ(parser.errorCount(), 0u);
    EXPECT_EQ(parser.transport(), Transport::NetBIOS);

    for (size_t i = 0; i < total; i++) {
        if (auto* v1 = parser.getV1Message(i))
            assembler.processV1Message(*v1);
        else if (auto* v2 = parser.getV2Message(i))
            assembler.processV2Message(*v2);
    }

    const auto& files = assembler.files();
    EXPECT_EQ(files.size(), 1u);
    auto it = files.begin();
    EXPECT_EQ(it->second.data.size(), 10u);
    EXPECT_EQ(it->second.bytes_read, 10u);
    EXPECT_EQ(it->second.is_complete, true);
    EXPECT_EQ(it->second.file_size, 12u);

    std::string expected = "HELLOWORLD";
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(it->second.data.data()), it->second.data.size()), expected);
}

TEST(IntegrationTest, JsonOutput) {
    auto stream = buildFileTransferStream();
    SMBParser parser;
    parser.feed(stream.data(), stream.size());
    parser.flush();

    auto j = parser.toJson();
    EXPECT_TRUE(j.is_array());
    EXPECT_EQ(j.size(), 7u);
    EXPECT_EQ(j[0]["command"], "SMB2_NEGOTIATE");
}
