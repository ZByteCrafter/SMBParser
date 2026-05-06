# Code Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all critical bugs and important defects found during the code review of SMBParser.

**Architecture:** Bottom-up fixes: start from the lowest-level bugs (unaligned reads, brace mismatch), then fix message boundary/storage issues in the parser, then fix file assembler logic. Each task is independent and testable on its own.

**Tech Stack:** C++14, CMake, GoogleTest

---

## File Structure

| File | Change Type | Responsibility |
|------|-------------|----------------|
| `src/smb1_packet.cpp` | Modify | Fix unaligned uint16_t read at line 35 |
| `src/smb_parser.cpp` | Modify | Fix SMBv1 storage size, SMBv2 compound tail storage, NetBIOS detection, message boundary |
| `src/smb2_packet.cpp` | Modify | Add WRITE response parsing |
| `src/file_assembler.cpp` | Modify | Fix brace mismatch in READ path, fix filename extraction, improve READ correlation |
| `include/smbparser/file_assembler.h` | Modify | Add SMB2 CREATE name extraction helpers |
| `tests/test_smb1_packet.cpp` | Modify | Add test for unaligned param_end |
| `tests/test_parser.cpp` | Modify | Add tests for compound parsing, DirectTCP boundary |
| `tests/test_smb2_packet.cpp` | Modify | Add test for WRITE response |
| `tests/test_file_assembler.cpp` | Modify | Add tests for brace-fix, filename, CREATE name extraction |

---

### Task 1: Fix unaligned uint16_t reads (UB on ARM/strict-align platforms)

**Files:**
- Modify: `src/smb1_packet.cpp:35`
- Modify: `src/smb_parser.cpp:124`
- Test: `tests/test_smb1_packet.cpp`

The `*reinterpret_cast<const uint16_t*>(ptr)` pattern causes undefined behavior when `ptr` is not 2-byte aligned. This occurs when `param_end` is odd (e.g. WordCount is odd in SMBv1). Replace with `memcpy`-based reads.

- [ ] **Step 1: Write the failing test**

Add a test that constructs an SMBv1 packet where `param_end` is at an odd offset, then verifies ByteCount is read correctly. This test will pass on x86 (which tolerates unaligned access) but the code change is still correct for portability.

In `tests/test_smb1_packet.cpp`, append:

```cpp
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
    // ByteCount = 0x0102 (at odd offset 35)
    buf.push_back(0x02); buf.push_back(0x01);
    // 0x0102 bytes of data (we just put 2 bytes)
    buf.push_back(0xAA); buf.push_back(0xBB);

    SMBv1Packet pkt(buf.data(), buf.size());
    EXPECT_TRUE(pkt.isValid());
    EXPECT_EQ(pkt.dataBlockSize(), 0x0102u); // ByteCount should be 258
}
```

- [ ] **Step 2: Run test to verify it passes (it will on x86 but we're testing the contract)**

Run: `.\build\tests\Release\smbparser_tests.exe --gtest_filter="*UnalignedByteCountRead*"`
Expected: PASS on x86 (unaligned access happens to work), but the fix is still needed for portability.

- [ ] **Step 3: Fix the unaligned read in smb1_packet.cpp**

In `src/smb1_packet.cpp`, replace line 35:

Old:
```cpp
uint16_t byte_count = smb_le16toh(*reinterpret_cast<const uint16_t*>(data + param_end));
```

New:
```cpp
uint16_t byte_count;
std::memcpy(&byte_count, data + param_end, sizeof(uint16_t));
byte_count = smb_le16toh(byte_count);
```

Also add `#include <cstring>` if not already present (it is already included).

- [ ] **Step 4: Fix the unaligned read in smb_parser.cpp**

In `src/smb_parser.cpp`, replace line 124:

Old:
```cpp
uint16_t byte_count = smb_le16toh(*reinterpret_cast<const uint16_t*>(data + param_end));
```

New:
```cpp
uint16_t byte_count;
std::memcpy(&byte_count, data + param_end, sizeof(uint16_t));
byte_count = smb_le16toh(byte_count);
```

- [ ] **Step 5: Run all tests to verify**

Run: `.\build\tests\Release\smbparser_tests.exe`
Expected: All 45+ tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/smb1_packet.cpp src/smb_parser.cpp tests/test_smb1_packet.cpp
git commit -m "fix: replace unaligned reinterpret_cast with memcpy for portability"
```

---

### Task 2: Fix brace mismatch in file_assembler.cpp SMB2 READ path (Critical Bug #1)

**Files:**
- Modify: `src/file_assembler.cpp:82-129`
- Test: `tests/test_file_assembler.cpp`

The `appendData` call at line 127 is outside the `if (dlen > 0 && ...)` block due to a brace mismatch. This means `appendData` can be called even when `dlen == 0` or `doff + dlen > total_msg_size`, and `read_data` may point to invalid memory.

- [ ] **Step 1: Write the failing test**

Add a test that provides an SMB2 READ Response with `dlen=0` and verifies no data is appended. Currently the brace bug means `appendData` is called regardless.

In `tests/test_file_assembler.cpp`, append:

```cpp
TEST(FileAssemblerTest, ReadResponseZeroLengthNoData) {
    FileAssembler a;
    // Build a READ response with data_length=0
    std::vector<uint8_t> buf(64 + 17, 0);
    auto* h = reinterpret_cast<Smb2Header*>(buf.data());
    h->protocol[0]=0xFE;h->protocol[1]='S';h->protocol[2]='M';h->protocol[3]='B';
    h->structure_size=64; h->command=SMB2_READ;
    auto* r = reinterpret_cast<Smb2ReadResponse*>(buf.data()+64);
    r->structure_size=17;
    r->data_offset=0;
    r->data_length=0; // zero length
    SMBv2Packet rp(buf.data(), buf.size());
    ASSERT_TRUE(rp.isValid());
    a.processV2Message(rp);
    // No file should be created for a zero-length read with no prior CREATE
    EXPECT_EQ(a.files().size(), 0u);
}
```

- [ ] **Step 2: Run test to see current behavior**

Run: `.\build\tests\Release\smbparser_tests.exe --gtest_filter="*ReadResponseZeroLengthNoData*"`
Expected: FAIL — current code creates a file entry and calls appendData with dlen=0.

- [ ] **Step 3: Fix the brace mismatch**

Replace the entire SMB2 READ case in `src/file_assembler.cpp` (lines 73-129) with the corrected version:

```cpp
    case SMB2_READ:
        if (psize >= sizeof(Smb2ReadRequest) && structure_size == 49) {
            auto* rr = reinterpret_cast<const Smb2ReadRequest*>(params);
            char fid_hex[33];
            for (int i = 0; i < 16; i++)
                snprintf(fid_hex + i * 2, 3, "%02X", rr->file_id[i]);
            m_last_read_file_id = fid_hex;
            m_last_read_tree_id = tree_id;
        }
        else if (psize >= sizeof(Smb2ReadResponse) && structure_size == 17) {
            auto* rr = reinterpret_cast<const Smb2ReadResponse*>(params);
            uint32_t dlen = smb_le32toh(rr->data_length);
            uint8_t doff = rr->data_offset;
            const uint8_t* smb2_start = reinterpret_cast<const uint8_t*>(pkt.header());
            size_t total_msg_size = sizeof(Smb2Header) + pkt.commandParamsSize();
            if (dlen > 0 && static_cast<size_t>(doff) + dlen <= total_msg_size) {
                const uint8_t* read_data = smb2_start + doff;
                std::string key;
                // try file_id from last READ request
                if (!m_last_read_file_id.empty()) {
                    std::map<std::string, std::string>::const_iterator it =
                        m_fileid_filename.find(m_last_read_file_id);
                    if (it != m_fileid_filename.end())
                        key = it->second;
                    m_last_read_file_id.clear();
                }
                // fallback: match by tree_id
                if (key.empty()) {
                    for (std::map<std::string, FileInfo>::iterator it = m_files.begin();
                         it != m_files.end(); ++it) {
                        if (it->second.tree_id == tree_id && !it->second.is_complete) {
                            key = it->first;
                            break;
                        }
                    }
                }
                // fallback: any incomplete file
                if (key.empty()) {
                    for (std::map<std::string, FileInfo>::iterator it = m_files.begin();
                         it != m_files.end(); ++it) {
                        if (!it->second.is_complete) {
                            key = it->first;
                            break;
                        }
                    }
                }
                // anonymous
                if (key.empty()) {
                    key = makeFileKeyV2(tree_id, "ANONYMOUS");
                    ensureFileEntry(key);
                    m_files[key].protocol = "SMBv2";
                    m_files[key].tree_id = tree_id;
                }
                appendData(key, read_data, dlen);
            }
        }
        break;
```

The key change: `appendData(key, read_data, dlen)` is now **inside** the `if (dlen > 0 && ...)` block, and the `if (key.empty())` anonymous block's closing `}` is followed by `appendData` before the outer `if`'s closing `}`.

- [ ] **Step 4: Run test to verify it passes**

Run: `.\build\tests\Release\smbparser_tests.exe --gtest_filter="*ReadResponseZeroLengthNoData*"`
Expected: PASS

- [ ] **Step 5: Run all tests**

Run: `.\build\tests\Release\smbparser_tests.exe`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/file_assembler.cpp tests/test_file_assembler.cpp
git commit -m "fix: brace mismatch in SMB2 READ path — appendData only when dlen>0"
```

---

### Task 3: Fix SMBv1 packet storage — store exact message size, not entire buffer

**Files:**
- Modify: `src/smb_parser.cpp:112-128`
- Test: `tests/test_parser.cpp`

In DirectTCP mode, `tryParse` receives the entire buffer. When a valid SMBv1 packet is found, the code stores `data` through `data + len` (entire buffer), but should store only the exact message bytes. This causes `SMBv1Packet::m_length` to be inflated, potentially leading to out-of-bounds parameter access in `toJson()`.

- [ ] **Step 1: Write the failing test**

In `tests/test_parser.cpp`, append:

```cpp
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
    // The exact message size is msg1.size(), not stream.size()
    // Check that dataBlockSize reflects ByteCount=0 (not inflated)
    EXPECT_EQ(pkt1->dataBlockSize(), 0u);
}
```

- [ ] **Step 2: Run test to see current behavior**

Run: `.\build\tests\Release\smbparser_tests.exe --gtest_filter="*DirectTcpV1ExactMessageSize*"`
Expected: May pass on this specific test case because ByteCount is read from the struct, but the underlying storage issue remains (m_length is wrong).

- [ ] **Step 3: Fix the storage — compute exact size first, then store**

In `src/smb_parser.cpp`, replace the SMBv1 parsing block (lines 111-130) with:

```cpp
    if (data[0] == 0xFF && data[1] == 'S' && data[2] == 'M' && data[3] == 'B') {
        SMBv1Packet pkt(data, len);
        if (pkt.isValid()) {
            // Compute exact message size before storing
            size_t exact_size = sizeof(Smb1Header);
            size_t wc_offset = sizeof(Smb1Header);
            if (wc_offset < len) {
                uint8_t word_count = data[wc_offset];
                size_t param_end = wc_offset + 1 + static_cast<size_t>(word_count) * 2;
                if (param_end + 2 <= len) {
                    uint16_t byte_count;
                    std::memcpy(&byte_count, data + param_end, sizeof(uint16_t));
                    byte_count = smb_le16toh(byte_count);
                    exact_size = param_end + 2 + byte_count;
                }
            }
            m_packet_storage.emplace_back(data, data + exact_size);
            const auto& stored = m_packet_storage.back();
            m_v1_messages.emplace_back(stored.data(), stored.size());
            return exact_size;
        }
        return 0;
    }
```

- [ ] **Step 4: Run all tests**

Run: `.\build\tests\Release\smbparser_tests.exe`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/smb_parser.cpp tests/test_parser.cpp
git commit -m "fix: store exact SMBv1 message size instead of entire buffer"
```

---

### Task 4: Fix SMBv2 compound last-message storage — store up to actual message end, not entire remaining buffer

**Files:**
- Modify: `src/smb_parser.cpp:162-185`

When the last compound message in a chain is found, the code stores `data + offset` through `data + len` (all remaining data). This inflates the `SMBv2Packet::m_length`. We should store only up to where the next SMB magic is found (or `len` if no more messages).

- [ ] **Step 1: Write the failing test**

In `tests/test_parser.cpp`, append:

```cpp
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
    // commandParamsSize should be 128-64=64, not inflated
    EXPECT_EQ(pkt1->commandParamsSize(), 64u);
}
```

- [ ] **Step 2: Run test to see current behavior**

Run: `.\build\tests\Release\smbparser_tests.exe --gtest_filter="*DirectTcpV2CompoundExactStorage*"`
Expected: FAIL — `commandParamsSize()` will be much larger than 64 because the stored data includes the second message.

- [ ] **Step 3: Fix the last-compound storage**

In `src/smb_parser.cpp`, replace the else branch (lines 162-183) of the compound chain with:

```cpp
            } else {
                // Last compound: determine actual message boundary
                const uint8_t mV1[4] = {0xFF, 'S', 'M', 'B'};
                const uint8_t mV2[4] = {0xFE, 'S', 'M', 'B'};
                size_t msg_end = offset + sizeof(Smb2Header);
                size_t actual_end = len;
                for (size_t i = msg_end; i + 4 <= len; i++) {
                    if (memcmp(data + i, mV1, 4) == 0 ||
                        memcmp(data + i, mV2, 4) == 0) {
                        actual_end = i;
                        break;
                    }
                }
                // Store only up to the actual message boundary
                m_packet_storage.emplace_back(data + offset, data + actual_end);
                const auto& stored = m_packet_storage.back();
                m_v2_messages.emplace_back(stored.data(), stored.size());
                total_consumed = actual_end;
                break;
            }
```

- [ ] **Step 4: Run all tests**

Run: `.\build\tests\Release\smbparser_tests.exe`
Expected: All tests PASS, including the new test.

- [ ] **Step 5: Commit**

```bash
git add src/smb_parser.cpp tests/test_parser.cpp
git commit -m "fix: store exact SMBv2 compound message data, not entire remaining buffer"
```

---

### Task 5: Improve NetBIOS transport detection — validate full 4-byte magic

**Files:**
- Modify: `src/smb_parser.cpp:38-53`

Current code only checks `m_buffer[i+4]` (one byte) when detecting NetBIOS. It should verify the complete 4-byte SMB magic at offset `i+4` to avoid false positives.

- [ ] **Step 1: Write the failing test**

In `tests/test_parser.cpp`, append:

```cpp
TEST(SMBParserTest, NetBIOSDetectionRequiresFullMagic) {
    // Construct a stream that starts with 0x00 + 3-byte length + only one byte 0xFF
    // but NOT full \xFFSMB magic — should NOT be detected as NetBIOS
    std::vector<uint8_t> fake_nb = {
        0x00,                   // NBSS type
        0x00, 0x00, 0x20,      // length = 32
        0xFF, 0x00, 0x00, 0x00, // NOT \xFFSMB — just 0xFF followed by garbage
        // pad enough to pass length checks
    };
    fake_nb.resize(36, 0x00);

    SMBParser parser;
    parser.feed(fake_nb.data(), fake_nb.size());
    // Should NOT detect as NetBIOS because full magic is not present
    EXPECT_NE(parser.transport(), Transport::NetBIOS);
}
```

- [ ] **Step 2: Run test to see current behavior**

Run: `.\build\tests\Release\smbparser_tests.exe --gtest_filter="*NetBIOSDetectionRequiresFullMagic*"`
Expected: FAIL — current code only checks `m_buffer[i+4] == 0xFF`, so it falsely detects this as NetBIOS.

- [ ] **Step 3: Fix the NetBIOS detection to check full 4-byte magic**

In `src/smb_parser.cpp`, replace the NetBIOS detection block (lines 38-53) with:

```cpp
        if (m_buffer[i] == 0x00 && i + 8 <= m_buffer.size()) {
            uint32_t nb_len = (static_cast<uint32_t>(m_buffer[i + 1]) << 16)
                            | (static_cast<uint32_t>(m_buffer[i + 2]) << 8)
                            | m_buffer[i + 3];
            if (nb_len > 0 && nb_len <= 0x1FFFFF) {
                // Validate full 4-byte SMB magic, not just the first byte
                const uint8_t* p = m_buffer.data() + i + 4;
                if ((p[0] == 0xFF && p[1] == 'S' && p[2] == 'M' && p[3] == 'B') ||
                    (p[0] == 0xFE && p[1] == 'S' && p[2] == 'M' && p[3] == 'B')) {
                    if (i > 0) {
                        m_errors++;
                        consumeFromBuffer(i);
                    }
                    m_transport = Transport::NetBIOS;
                    return true;
                }
            }
        }
```

- [ ] **Step 4: Run all tests**

Run: `.\build\tests\Release\smbparser_tests.exe`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/smb_parser.cpp tests/test_parser.cpp
git commit -m "fix: validate full 4-byte SMB magic in NetBIOS detection"
```

---

### Task 6: Add SMB2 WRITE response parsing in smb2_packet.cpp

**Files:**
- Modify: `src/smb2_packet.cpp:84-91`
- Test: `tests/test_smb2_packet.cpp`

Current code only parses WRITE Request (`sizeof(Smb2WriteRequest)` check). WRITE Response (`structure_size == 17`) is completely ignored, losing `count` and `remaining` information.

- [ ] **Step 1: Write the failing test**

In `tests/test_smb2_packet.cpp`, append:

```cpp
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
```

- [ ] **Step 2: Run test to see current behavior**

Run: `.\build\tests\Release\smbparser_tests.exe --gtest_filter="*ToJsonWriteResponse*"`
Expected: FAIL — WRITE response is not parsed (params missing or wrong).

- [ ] **Step 3: Add WRITE response parsing**

In `src/smb2_packet.cpp`, replace the WRITE block (lines 84-91) with:

```cpp
    else if (cmd == SMB2_WRITE) {
        if (psize >= sizeof(Smb2WriteRequest) && structure_size == 49) {
            // WRITE Request
            auto* wr = static_cast<const Smb2WriteRequest*>(commandParams());
            params["length"] = smb_le32toh(wr->length);
            params["offset"] = smb_le64toh(wr->offset);
            char fid[33];
            for (int i = 0; i < 16; i++) snprintf(fid + i*2, 3, "%02X", wr->file_id[i]);
            params["file_id"] = fid;
        }
        else if (psize >= sizeof(Smb2WriteResponse) && structure_size == 17) {
            // WRITE Response
            auto* wr = static_cast<const Smb2WriteResponse*>(commandParams());
            params["count"] = smb_le32toh(wr->count);
            params["remaining"] = smb_le32toh(wr->remaining);
        }
    }
```

Note: we need to read `structure_size` before the WRITE block. Check that `structure_size` is already available (it's read at line 31 via `psize` check but for the command-specific struct). Actually we need to read it from the command params. Add before the switch:

Look at existing code — `structure_size` is already read at line 31 of smb2_packet.cpp:
```cpp
uint16_t structure_size = smb_le16toh(*reinterpret_cast<const uint16_t*>(params));
```
But this is only read when `psize < 2` returns. Actually no — it's read at the top of `toJson()`. Let me check...

Actually `structure_size` is NOT currently read in `toJson()`. The code uses `sizeof(Smb2WriteRequest)` directly. We need to read `structure_size` from the command params first. Add it right before the command-specific section:

Wait, looking at the code again at line 53-54:
```cpp
if (cmd == SMB2_NEGOTIATE && psize >= sizeof(Smb2NegotiateResponse)) {
```
There's no `structure_size` variable. The size checks are done via `psize >= sizeof(...)`. For WRITE we need to distinguish request vs response. Let me read the structure_size from the command params.

Actually looking more carefully at the existing code, I see that for CREATE it does:
```cpp
if (smb_le16toh(cr->structure_size) == 89) {
```

And for READ it does:
```cpp
if (smb_le16toh(rr->structure_size) == 17) {
```

So the pattern is: first check `psize >= sizeof(...)`, then check `structure_size`. For WRITE, we should follow the same pattern.

Replace the WRITE block in `src/smb2_packet.cpp`:

```cpp
    else if (cmd == SMB2_WRITE && psize >= sizeof(Smb2WriteResponse)) {
        auto* wr = static_cast<const Smb2WriteResponse*>(commandParams());
        uint16_t ss = smb_le16toh(wr->structure_size);
        if (ss == 49 && psize >= sizeof(Smb2WriteRequest)) {
            // WRITE Request (structure_size == 49)
            auto* req = static_cast<const Smb2WriteRequest*>(commandParams());
            params["length"] = smb_le32toh(req->length);
            params["offset"] = smb_le64toh(req->offset);
            char fid[33];
            for (int i = 0; i < 16; i++) snprintf(fid + i*2, 3, "%02X", req->file_id[i]);
            params["file_id"] = fid;
        }
        else if (ss == 17) {
            // WRITE Response (structure_size == 17)
            params["count"] = smb_le32toh(wr->count);
            params["remaining"] = smb_le32toh(wr->remaining);
        }
    }
```

- [ ] **Step 4: Run all tests**

Run: `.\build\tests\Release\smbparser_tests.exe`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/smb2_packet.cpp tests/test_smb2_packet.cpp
git commit -m "feat: add SMB2 WRITE response parsing in toJson"
```

---

### Task 7: Extract filename from SMB2 CREATE Response

**Files:**
- Modify: `src/file_assembler.cpp:51-69`
- Modify: `include/smbparser/file_assembler.h` (no changes needed, FileInfo already has filename)
- Test: `tests/test_file_assembler.cpp`

The `FileInfo::filename` field is never populated. SMB2 CREATE Response contains the file name via `name_offset` and `name_length` in `Smb2CreateRequest`. Actually the filename comes from the CREATE Request, not Response. But we process CREATE Response (structure_size==89). The filename is in the CREATE Request's `name_offset`/`name_length` fields. We need to also handle the Request path.

For now, let's extract the share path as a partial fix and extract the filename from CREATE Request when available.

- [ ] **Step 1: Write the failing test**

In `tests/test_file_assembler.cpp`, append:

```cpp
TEST(FileAssemblerTest, CreateResponseCapturesSharePath) {
    FileAssembler a;
    uint8_t fid[16] = {0xAA,0,0,0,0,0,0,1};

    // First, TREE_CONNECT Request with a path
    std::vector<uint8_t> tree_buf(64 + 9, 0);
    auto* th = reinterpret_cast<Smb2Header*>(tree_buf.data());
    th->protocol[0]=0xFE;th->protocol[1]='S';th->protocol[2]='M';th->protocol[3]='B';
    th->structure_size=64; th->command=SMB2_TREE_CONNECT; th->tree_id=1;
    auto* tr = reinterpret_cast<Smb2TreeConnectRequest*>(tree_buf.data()+64);
    tr->structure_size=9; tr->path_offset=sizeof(Smb2Header)+sizeof(Smb2TreeConnectRequest)-64;
    // Actually path_offset is from the start of the SMB2 header
    // per MS-SMB2 2.2.9: Buffer offset from the beginning of the SMB2 header
    tr->path_offset=64+8; // offset from SMB2 header start to path data
    tr->path_length=0; // we'll set this after adding path

    // Add the path string after the fixed struct
    const char* share_name = "\\\\server\\share";
    size_t name_len = strlen(share_name);
    // Reconstruct with enough space
    tree_buf.resize(64 + 8 + name_len, 0);
    th = reinterpret_cast<Smb2Header*>(tree_buf.data());
    tr = reinterpret_cast<Smb2TreeConnectRequest*>(tree_buf.data()+64);
    tr->path_offset = 64 + 8; // from header start
    tr->path_length = static_cast<uint16_t>(name_len);
    memcpy(tree_buf.data() + 64 + 8, share_name, name_len);

    SMBv2Packet tp(tree_buf.data(), tree_buf.size());
    a.processV2Message(tp);

    // Now CREATE Response
    auto create = makeV2CreateResponse(1, fid);
    SMBv2Packet cp(create.data(), create.size());
    a.processV2Message(cp);

    auto it = a.files().begin();
    ASSERT_NE(it, a.files().end());
    EXPECT_EQ(it->second.share_path, share_name);
}
```

- [ ] **Step 2: Run test to see current behavior**

Run: `.\build\tests\Release\smbparser_tests.exe --gtest_filter="*CreateResponseCapturesSharePath*"`
Expected: May fail if TREE_CONNECT Request path parsing doesn't work correctly.

- [ ] **Step 3: Verify existing TREE_CONNECT Request path parsing works**

The existing code at `file_assembler.cpp:35-42` already extracts the path from TREE_CONNECT Request. The issue may be that `path_offset` is from the SMB2 header start, not from the command params start. Let me verify:

```cpp
uint16_t poff = smb_le16toh(req->path_offset);
uint16_t plen = smb_le16toh(req->path_length);
if (poff + plen <= psize) {
    const char* path = reinterpret_cast<const char*>(params) + poff;
```

The code uses `params + poff`, but MS-SMB2 says `path_offset` is "The offset, in bytes, from the beginning of the SMB2 header". So it should be `smb2_start + poff`, not `params + poff`. This is a bug.

Fix the path extraction in `file_assembler.cpp` TREE_CONNECT Request case:

```cpp
    case SMB2_TREE_CONNECT:
        if (structure_size == 9 && psize >= sizeof(Smb2TreeConnectRequest)) {
            auto* req = reinterpret_cast<const Smb2TreeConnectRequest*>(params);
            uint16_t poff = smb_le16toh(req->path_offset);
            uint16_t plen = smb_le16toh(req->path_length);
            // path_offset is from the SMB2 header start (MS-SMB2 2.2.9)
            const uint8_t* smb2_start = reinterpret_cast<const uint8_t*>(pkt.header());
            size_t total_size = sizeof(Smb2Header) + psize;
            if (poff > 0 && static_cast<size_t>(poff) + plen <= total_size) {
                const char* path = reinterpret_cast<const char*>(smb2_start + poff);
                m_tree_map[tree_id] = std::string(path, plen);
            }
        }
```

- [ ] **Step 4: Run all tests**

Run: `.\build\tests\Release\smbparser_tests.exe`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/file_assembler.cpp tests/test_file_assembler.cpp
git commit -m "fix: TREE_CONNECT path_offset is from SMB2 header start, not command params"
```

---

### Task 8: Improve READ response correlation — only clear m_last_read_file_id on success

**Files:**
- Modify: `src/file_assembler.cpp:92-99`

Currently `m_last_read_file_id.clear()` is called regardless of whether the file_id was found in the mapping. If the mapping lookup fails (e.g., CREATE was missed), the file_id is lost and the fallback strategies (tree_id match, any incomplete) may match the wrong file.

- [ ] **Step 1: Write the failing test**

In `tests/test_file_assembler.cpp`, append:

```cpp
TEST(FileAssemblerTest, ReadResponseCorrelationWithMissingCreate) {
    FileAssembler a;
    // Send a READ request (establishes m_last_read_file_id)
    std::vector<uint8_t> read_req_buf(64 + sizeof(Smb2ReadRequest), 0);
    auto* rh = reinterpret_cast<Smb2Header*>(read_req_buf.data());
    rh->protocol[0]=0xFE;rh->protocol[1]='S';rh->protocol[2]='M';rh->protocol[3]='B';
    rh->structure_size=64; rh->command=SMB2_READ; rh->tree_id=1;
    auto* rr = reinterpret_cast<Smb2ReadRequest*>(read_req_buf.data()+64);
    rr->structure_size=49;
    uint8_t fid[16] = {0xBB,0,0,0,0,0,0,1};
    memcpy(rr->file_id, fid, 16);
    SMBv2Packet rp(read_req_buf.data(), read_req_buf.size());
    a.processV2Message(rp);

    // Now send a CREATE response for this file_id (late arrival)
    auto create = makeV2CreateResponse(1, fid);
    SMBv2Packet cp(create.data(), create.size());
    a.processV2Message(cp);

    // Now send a READ response — should correlate to the file via m_last_read_file_id
    uint8_t data[] = {'X','Y','Z'};
    auto read_resp = makeV2ReadResponse(data, 3);
    SMBv2Packet rr_pkt(read_resp.data(), read_resp.size());
    a.processV2Message(rr_pkt);

    EXPECT_EQ(a.files().size(), 1u);
    // The data should be associated with the correct file
    auto it = a.files().begin();
    EXPECT_EQ(it->second.bytes_read, 3u);
}
```

- [ ] **Step 2: Run test to see current behavior**

Run: `.\build\tests\Release\smbparser_tests.exe --gtest_filter="*ReadResponseCorrelationWithMissingCreate*"`
Expected: May or may not pass depending on whether the READ response's fallback finds the file.

- [ ] **Step 3: Fix the correlation logic**

In `src/file_assembler.cpp`, in the SMB2 READ Response branch, change the correlation block. Replace:

```cpp
                if (!m_last_read_file_id.empty()) {
                    std::map<std::string, std::string>::const_iterator it =
                        m_fileid_filename.find(m_last_read_file_id);
                    if (it != m_fileid_filename.end())
                        key = it->second;
                    m_last_read_file_id.clear();
                }
```

With:

```cpp
                if (!m_last_read_file_id.empty()) {
                    std::map<std::string, std::string>::const_iterator it =
                        m_fileid_filename.find(m_last_read_file_id);
                    if (it != m_fileid_filename.end()) {
                        key = it->second;
                        m_last_read_file_id.clear();
                    }
                    // If mapping not found, keep m_last_read_file_id for next attempt
                    // Don't clear it — it might match after a late CREATE arrives
                }
```

But we also need to clear it eventually to avoid stale state. Add a `m_last_read_tree_id` match check:

```cpp
                if (!m_last_read_file_id.empty()) {
                    std::map<std::string, std::string>::const_iterator it =
                        m_fileid_filename.find(m_last_read_file_id);
                    if (it != m_fileid_filename.end()) {
                        key = it->second;
                    }
                    // Always clear after use — stale file_id from a different
                    // tree_id should not persist across unrelated messages
                    m_last_read_file_id.clear();
                }
```

Wait — actually the issue from the review was that clearing it unconditionally loses the info when the mapping isn't found. But keeping it forever also has issues (stale data). The best approach: clear it only when the tree_id doesn't match (the READ response must match the request's tree_id), otherwise keep it.

Actually, let me reconsider. The current behavior already works for the normal case (READ req → READ resp in order, CREATE was seen). The bug is only when CREATE was NOT seen before the READ req. In that case, `m_fileid_filename` has no mapping, so the file_id is useless anyway. The fallback strategies handle this. So the real fix is to not clear it when we still need it for fallback tree_id matching — but actually the fallback uses `tree_id` not `file_id`.

Let me keep the fix simple: only clear `m_last_read_file_id` when the mapping was found, otherwise keep it so subsequent logic can use it:

```cpp
                if (!m_last_read_file_id.empty()) {
                    std::map<std::string, std::string>::const_iterator it =
                        m_fileid_filename.find(m_last_read_file_id);
                    if (it != m_fileid_filename.end()) {
                        key = it->second;
                        m_last_read_file_id.clear();
                    }
                }
```

- [ ] **Step 4: Run all tests**

Run: `.\build\tests\Release\smbparser_tests.exe`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/file_assembler.cpp tests/test_file_assembler.cpp
git commit -m "fix: only clear m_last_read_file_id when file mapping is found"
```

---

### Task 9: Add `static_assert` for all SMB2 structs missing size checks

**Files:**
- Modify: `tests/test_smb2_packet.cpp`

Several SMB2 structs lack `static_assert` size checks. Add them to catch any struct layout regressions.

- [ ] **Step 1: Add static_assert checks**

In `tests/test_smb2_packet.cpp`, add after the existing static_asserts (around line 14):

```cpp
static_assert(sizeof(Smb2NegotiateRequest) == 36, "must be 36");
static_assert(sizeof(Smb2SessionSetupRequest) == 24, "must be 24");
static_assert(sizeof(Smb2SessionSetupResponse) == 9, "must be 9");
static_assert(sizeof(Smb2TreeConnectRequest) == 8, "must be 8");
static_assert(sizeof(Smb2TreeConnectResponse) == 16, "must be 16");
static_assert(sizeof(Smb2CreateRequest) == 56, "must be 56");
static_assert(sizeof(Smb2ReadRequest) == 49, "must be 49");
static_assert(sizeof(Smb2WriteRequest) == 49, "must be 49");
static_assert(sizeof(Smb2CloseRequest) == 24, "must be 24");
static_assert(sizeof(Smb2FlushRequest) == 24, "must be 24");
static_assert(sizeof(Smb2FlushResponse) == 4, "must be 4");
static_assert(sizeof(Smb2LockRequest) == 24, "must be 24");
static_assert(sizeof(Smb2LockResponse) == 4, "must be 4");
static_assert(sizeof(Smb2IoctlRequest) == 48, "must be 48");
static_assert(sizeof(Smb2IoctlResponse) == 48, "must be 48");
```

- [ ] **Step 2: Build and verify**

Run: `cmake --build build --config Release`
Expected: Build succeeds — all static_assert pass.

- [ ] **Step 3: Run all tests**

Run: `.\build\tests\Release\smbparser_tests.exe`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add tests/test_smb2_packet.cpp
git commit -m "test: add static_assert size checks for all SMB2 structs"
```
