#include <gtest/gtest.h>
#include <smbparser/file_assembler.h>
#include <smbparser/smb2_structs.h>
#include <smbparser/smb2_packet.h>
#include <smbparser/smb1_structs.h>
#include <smbparser/smb1_packet.h>
#include <smbparser/types.h>
#include <vector>
#include <cstring>

using namespace smbparser;

static std::vector<uint8_t> makeV2CreateResponse(uint32_t tid, const uint8_t* fid) {
    std::vector<uint8_t> buf(64 + 89);
    auto* h = reinterpret_cast<Smb2Header*>(buf.data());
    h->protocol[0]=0xFE;h->protocol[1]='S';h->protocol[2]='M';h->protocol[3]='B';
    h->structure_size=64; h->command=SMB2_CREATE; h->tree_id=tid;
    auto* r = reinterpret_cast<Smb2CreateResponse*>(buf.data()+64);
    r->structure_size=89; r->end_of_file=10;
    memcpy(r->file_id, fid, 16);
    return buf;
}

static std::vector<uint8_t> makeV2ReadResponse(const uint8_t* data, size_t len) {
    std::vector<uint8_t> buf(64 + 17 + len);
    auto* h = reinterpret_cast<Smb2Header*>(buf.data());
    h->protocol[0]=0xFE;h->protocol[1]='S';h->protocol[2]='M';h->protocol[3]='B';
    h->structure_size=64; h->command=SMB2_READ;
    auto* r = reinterpret_cast<Smb2ReadResponse*>(buf.data()+64);
    r->structure_size=17; r->data_offset=static_cast<uint8_t>(sizeof(Smb2Header) + sizeof(Smb2ReadResponse)); r->data_length=static_cast<uint32_t>(len);
    memcpy(buf.data()+64+17, data, len);
    return buf;
}

TEST(FileAssemblerTest, TrackFileViaV2Messages) {
    FileAssembler a;
    uint8_t fid[16] = {0xFF,0,0,0,0,0,0,1};
    auto create = makeV2CreateResponse(1, fid);
    SMBv2Packet cp(create.data(), create.size());
    a.processV2Message(cp);

    uint8_t d[] = {'H','E','L','L','O'};
    auto read = makeV2ReadResponse(d, 5);
    SMBv2Packet rp(read.data(), read.size());
    a.processV2Message(rp);

    EXPECT_EQ(a.files().size(), 1u);
    auto it = a.files().begin();
    EXPECT_EQ(it->second.bytes_read, 5u);
    EXPECT_EQ(it->second.data[0], 'H');
    EXPECT_FALSE(it->second.is_complete);
}

TEST(FileAssemblerTest, ToJsonOutput) {
    FileAssembler a;
    uint8_t fid[16] = {1};
    auto create = makeV2CreateResponse(1, fid);
    SMBv2Packet cp(create.data(), create.size());
    a.processV2Message(cp);
    auto j = a.toJson();
    EXPECT_TRUE(j.contains("files"));
    EXPECT_EQ(j["files"].size(), 1u);
}

TEST(FileAssemblerTest, MultipleFilesDontConfuse) {
    FileAssembler a;
    uint8_t f1[16] = {1}; uint8_t f2[16] = {2};
    auto c1 = makeV2CreateResponse(1, f1);
    auto c2 = makeV2CreateResponse(1, f2);
    a.processV2Message(SMBv2Packet(c1.data(), c1.size()));
    a.processV2Message(SMBv2Packet(c2.data(), c2.size()));
    EXPECT_EQ(a.files().size(), 2u);
}

TEST(FileAssemblerTest, MissingMetadataTolerant) {
    FileAssembler a;
    uint8_t d[] = {'X','Y','Z'};
    auto read = makeV2ReadResponse(d, 3);
    SMBv2Packet rp(read.data(), read.size());
    a.processV2Message(rp);
    EXPECT_EQ(a.files().size(), 1u);
    EXPECT_EQ(a.files().begin()->second.bytes_read, 3u);
}
