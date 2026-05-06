# AGENTS.md

## Build & Test

```bash
# Configure (requires network for FetchContent on first run)
cmake -B build -S . -DBUILD_TESTING=ON

# Build
cmake --build build

# Run all tests (51 tests, 8 suites)
.\build\tests\Release\smbparser_tests.exe   # Windows
./build/tests/smbparser_tests                # Linux

# Run a single test suite
.\build\tests\Release\smbparser_tests.exe --gtest_filter="*SMBParser*"

# Build without tests
cmake -B build -S . -DBUILD_TESTING=OFF
```

Dependencies are fetched via `FetchContent` (nlohmann::json v3.11.3, GoogleTest v1.14.0). First configure downloads ~20MB. Subsequent configures are cached in `build/_deps/`.

## Architecture

Single static library (`smbparser`). Bottom-up dependency order:

```
types.h + smb1_structs.h + smb2_structs.h   ← packed structs, shared by all
    ↓
stream_reader.h                              ← validated buffer reads (header-only)
    ↓
smb1_packet.cpp + smb2_packet.cpp            ← single-message parse + toJson
    ↓
smb_parser.cpp                               ← TCP stream: transport detect, reassembly, error recovery
    ↓
file_assembler.cpp                           ← cross-message file tracking + data aggregation
```

## Key Conventions

### Packed structs

All SMB wire-format structs are defined with `PACKED_STRUCT_BEGIN` / `PACKED_STRUCT_END` (cross-platform macros in `types.h`). Fixed fields are accessed via `reinterpret_cast`. Add `static_assert(sizeof(Struct) == N)` for every struct. Variable-length fields use offset + validated bounds check — never raw pointer arithmetic.

**Note:** MS-SMB2 `structure_size` includes a 1-byte buffer prefix that the C struct does **not** include. E.g. `Smb2ReadRequest` has `structure_size == 49` in the protocol but `sizeof(Smb2ReadRequest) == 48` in C (packed). When checking `psize >= sizeof(Struct)` and also checking `structure_size` from wire data, use the protocol value (49), not `sizeof` (48).

### Unaligned reads

**Never** do `*reinterpret_cast<const uint16_t*>(ptr)` — it's UB when `ptr` is not 2-byte aligned (happens when SMBv1 `WordCount` is odd, making `param_end` odd). Use `std::memcpy` + `smb_le16toh` instead:

```cpp
uint16_t val;
std::memcpy(&val, data + offset, sizeof(uint16_t));
val = smb_le16toh(val);
```

### Endian conversion

Use `smb_le16toh`, `smb_le32toh`, `smb_le64toh` — **NOT** `le16toh` (name conflicts with glibc `<endian.h>` on Linux). On little-endian hosts these are identity no-ops. Defined in `types.h`.

### Validation gate

Before `reinterpret_cast` on external data, always validate:
1. Buffer length ≥ minimum struct size
2. Magic bytes (SMBv1: `0xFF"SMB"`, SMBv2: `0xFE"SMB"`)
3. Structure consistency (WordCount/ByteCount for V1, structure_size for V2)

Invalid messages → set `m_valid = false` + `m_error`, never crash.

### to_string functions

`smb1_command_to_string` etc. return `std::string` (not `const char*`). No static buffers — thread-safe.

### Tests

Follow the existing TDD layers: `test_types.cpp` → `test_stream_reader.cpp` → `test_smb1_structs.cpp` / `test_smb2_packet.cpp` → `test_parser.cpp` → `test_file_assembler.cpp` → `test_integration.cpp`. New structs get `static_assert` size checks + field-access tests.

## Gotchas

- **Single-threaded only.** No locks, no atomics. The four to_string functions are safe regardless.
- **C++14** — no `std::optional`, `std::string_view`, `std::byte`, `std::span`.
- **SMBv2 compounding** — `next_command` chain parsed with a **loop** (not recursion) to avoid stack overflow. In `smb_parser.cpp`, each compound segment is stored up to its actual boundary (next `next_command` offset or next SMB magic), NOT the entire remaining buffer tail. See the three `emplace_back` paths in `tryParse`.
- **DirectTCP message boundaries** — no explicit length field. Parser uses struct sizes + SMB magic scanning to determine where one message ends. `consumeFromBuffer` must use the exact consumed size returned by `tryParse`, never `m_buffer.size()`.
- **Packet storage size** — `m_packet_storage` must store only the exact message bytes, not the full buffer. SMBv1 computes `exact_size` from WordCount+ByteCount first; SMBv2 scans for next magic to find `actual_end`. Storing more inflates `m_length` and can cause out-of-bounds reads in `toJson()`.
- **NetBIOS mode** — expects 4-byte NBSS header (type=0x00 + 3-byte big-endian length). Detection validates the full 4-byte SMB magic at offset+4, not just the first byte.
- **FileAssembler READ correlation** — SMBv2 READ response has no file_id. Assembler tracks `m_last_read_file_id` from the preceding READ request, falling back to tree_id match. `m_last_read_file_id` is only cleared when the mapping is found in `m_fileid_filename`; if not found, it's preserved for the next attempt.
- **`data_offset` interpretation** — BOTH SMBv1 and SMBv2 use absolute offset from the SMB header start. This is easy to get wrong and has caused bugs in both directions. The code uses `reinterpret_cast<const uint8_t*>(pkt.header()) + doff` consistently. **This applies to READ_ANDX, WRITE_ANDX, SMB2_READ, and SMB2_WRITE. Do not miss the WRITE paths.**
- **`Smb2ReadResponse` struct layout** — `data_offset` is `uint8_t` (1 byte), followed by `uint8_t reserved`. Do NOT change it to `uint16_t` — the struct size stays 17 either way, but the field alignment shifts, `reserved` disappears, and all subsequent fields read wrong values. Verified by `static_assert(sizeof(Smb2ReadResponse) == 17)`.
- **SMB2_TREE_CONNECT** — `file_assembler.cpp` handles both Request (`structure_size==9`) and Response (`structure_size==16`). Adding new TREE_CONNECT logic must cover both paths; Response-only streams otherwise fail to populate `m_tree_map`.
- **TREE_CONNECT `path_offset`** — In `Smb2TreeConnectRequest`, `path_offset` is from the SMB2 **header** start (MS-SMB2 §2.2.9), not from the command params start. Use `smb2_start + poff`, not `params + poff`.
- **SMB2 WRITE Request vs Response** — `toJson()` distinguishes them by `structure_size`: Request is 49, Response is 17. Both must be handled. Same pattern for READ (Request 49, Response 17).
- **Encrypted packets** — `file_assembler.cpp:processV2Message` checks `SMB2_FLAGS_ENCRYPTED (0x04)` on entry and skips them. Do not remove this gate without adding decryption support.
- **TRANSACT2/NT_TRANSACT** sub-commands parse the outer header but do not deeply parse sub-function parameters.
