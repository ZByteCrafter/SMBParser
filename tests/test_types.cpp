#include <gtest/gtest.h>
#include <smbparser/types.h>
#include <cstring>

PACKED_STRUCT_BEGIN
struct TestPacked { uint8_t a; uint32_t b; uint16_t c; };
PACKED_STRUCT_END
static_assert(sizeof(TestPacked) == 7, "packed struct must be 7 bytes");

TEST(TypesTest, CompilesAndLinks) {
    EXPECT_TRUE(true);
}

TEST(TypesTest, EndianConversion) {
    uint8_t buf[] = {0x02, 0x01, 0x04, 0x03, 0x02, 0x01};
    uint16_t v16 = smbparser::smb_le16toh(*reinterpret_cast<uint16_t*>(buf));
    EXPECT_EQ(v16, 0x0102u);
    uint32_t v32 = smbparser::smb_le32toh(*reinterpret_cast<uint32_t*>(buf + 2));
    EXPECT_EQ(v32, 0x01020304u);
}

TEST(TypesTest, Smb1CommandToString) {
    EXPECT_EQ(smbparser::smb1_command_to_string(0x72), "SMB_COM_NEGOTIATE");
    EXPECT_EQ(smbparser::smb1_command_to_string(0x2E), "SMB_COM_READ_ANDX");
    EXPECT_EQ(smbparser::smb1_command_to_string(0xFF), "UNKNOWN_0xFF");
}

TEST(TypesTest, Smb2CommandToString) {
    EXPECT_EQ(smbparser::smb2_command_to_string(0x0000), "SMB2_NEGOTIATE");
    EXPECT_EQ(smbparser::smb2_command_to_string(0x0008), "SMB2_READ");
    EXPECT_EQ(smbparser::smb2_command_to_string(0xFFFF), "UNKNOWN_0xFFFF");
}

TEST(TypesTest, NtStatusToString) {
    EXPECT_EQ(smbparser::ntstatus_to_string(0x00000000), "STATUS_SUCCESS");
    EXPECT_EQ(smbparser::ntstatus_to_string(0xC0000022), "STATUS_ACCESS_DENIED");
    EXPECT_EQ(smbparser::ntstatus_to_string(0xDEADBEEF), "NTSTATUS_0xDEADBEEF");
}

TEST(TypesTest, DialectToString) {
    EXPECT_EQ(smbparser::smb2_dialect_to_string(0x0210), "2.1");
    EXPECT_EQ(smbparser::smb2_dialect_to_string(0x0311), "3.1.1");
}
