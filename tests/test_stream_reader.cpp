#include <gtest/gtest.h>
#include <smbparser/stream_reader.h>
#include <smbparser/types.h>

using namespace smbparser;

TEST(StreamReaderTest, ReadsUint16WithinBounds) {
    uint8_t data[] = {0x02, 0x01};
    StreamReader reader(data, sizeof(data));
    uint16_t val;
    EXPECT_TRUE(reader.read(0, val));
    EXPECT_EQ(val, smb_le16toh(0x0102u));
}

TEST(StreamReaderTest, ReadOutOfBoundsReturnsFalse) {
    uint8_t data[] = {0x01, 0x02, 0x03};
    StreamReader reader(data, sizeof(data));
    uint32_t val;
    EXPECT_FALSE(reader.read(1, val));
    EXPECT_FALSE(reader.read(3, val));
}

TEST(StreamReaderTest, CanReadReturnsCorrectly) {
    uint8_t data[10] = {};
    StreamReader reader(data, 10);
    EXPECT_TRUE(reader.canRead(0, 10));
    EXPECT_TRUE(reader.canRead(5, 5));
    EXPECT_FALSE(reader.canRead(8, 3));
    EXPECT_FALSE(reader.canRead(10, 1));
}

TEST(StreamReaderTest, LengthReturnsCorrectValue) {
    uint8_t data[42] = {};
    StreamReader reader(data, 42);
    EXPECT_EQ(reader.length(), 42u);
}

TEST(StreamReaderTest, ReadsUint32AtOffset) {
    uint8_t data[] = {0x00, 0x00, 0x04, 0x03, 0x02, 0x01};
    StreamReader reader(data, sizeof(data));
    uint32_t val;
    EXPECT_TRUE(reader.read(2, val));
    EXPECT_EQ(val, smb_le32toh(0x01020304u));
}

TEST(StreamReaderTest, ReadsBytesPointer) {
    uint8_t data[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    StreamReader reader(data, sizeof(data));
    const uint8_t* ptr = nullptr;
    EXPECT_TRUE(reader.readBytes(1, 3, ptr));
    EXPECT_EQ(ptr[0], 0xBB);
    EXPECT_EQ(ptr[1], 0xCC);
    EXPECT_EQ(ptr[2], 0xDD);
}

TEST(StreamReaderTest, ReadsBytesOutOfBoundsReturnsFalse) {
    uint8_t data[] = {0xAA, 0xBB, 0xCC};
    StreamReader reader(data, sizeof(data));
    const uint8_t* ptr = nullptr;
    EXPECT_FALSE(reader.readBytes(1, 5, ptr));
    EXPECT_FALSE(reader.readBytes(3, 1, ptr));
}

TEST(StreamReaderTest, ReadsAsciiString) {
    uint8_t data2[] = {'H','E','L','L','O','\0','W'};
    StreamReader reader2(data2, sizeof(data2));
    std::string s;
    EXPECT_TRUE(reader2.readString(0, 10, s, false));
    EXPECT_EQ(s, "HELLO");
}

TEST(StreamReaderTest, ReadsUnicodeString) {
    uint8_t data[] = {0x41,0x00, 0x42,0x00, 0x43,0x00, 0x00,0x00};
    StreamReader reader(data, sizeof(data));
    std::string s;
    EXPECT_TRUE(reader.readString(0, 4, s, true));
    EXPECT_EQ(s, "ABC");
}

TEST(StreamReaderTest, ReadStringBoundsCheck) {
    uint8_t data[] = {0x41, 0x00};
    StreamReader reader(data, sizeof(data));
    std::string s;
    EXPECT_TRUE(reader.readString(0, 5, s, true));
    EXPECT_TRUE(reader.readString(0, 5, s, false));
}
