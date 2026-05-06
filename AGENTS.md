# AGENTS.md

## Build & Test

```bash
# Configure (requires network for FetchContent on first run)
cmake -B build -S . -DBUILD_TESTING=ON

# Build
cmake --build build

# Run all tests (45 tests, 8 suites)
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

### Packed structs (reinterpret_cast)

All SMB wire-format structs are defined with `PACKED_STRUCT_BEGIN` / `PACKED_STRUCT_END` (cross-platform macros in `types.h`). Fixed fields are accessed via `reinterpret_cast`. Add `static_assert(sizeof(Struct) == N)` for every struct. Variable-length fields use offset + validated bounds check — never raw pointer arithmetic.

### Endian conversion

Use `smb_le16toh`, `smb_le32toh`, `smb_le64toh` — **NOT** `le16toh` (name conflicts with glibc `<endian.h>` on Linux). On little-endian hosts these are identity no-ops. Defined in `types.h`.

### Validation gate

Before `reinterpret_cast` on external data, always validate:
1. Buffer length ≥ minimum struct size
2. Magic bytes (SMBv1: `0xFF"SMB"`, SMBv2: `0xFE"SMB"`)
3. Structure consistency (WordCount/ByteCount for V1, structure_size for V2)

Invalid messages → set `m_valid = false` + `m_error`, never crash.

### to_string functions

`smtb1_command_to_string` etc. return `std::string` (not `const char*`). No static buffers — thread-safe.

### Tests

Follow the existing TDD layers: `test_types.cpp` → `test_stream_reader.cpp` → `test_smb1_structs.cpp` / `test_smb2_packet.cpp` → `test_parser.cpp` → `test_file_assembler.cpp` → `test_integration.cpp`. New structs get `static_assert` size checks + field-access tests.

## Gotchas

- **Single-threaded only.** No locks, no atomics. The four to_string functions are now safe regardless.
- **C++14** — no `std::optional`, `std::string_view`, `std::byte`, `std::span`.
- **SMBv2 compounding** — `next_command` chain parsed with a **loop** (not recursion) to avoid stack overflow.
- **DirectTCP message boundaries** — no explicit length field. Parser uses struct sizes + SMB magic scanning to determine where one message ends. `consumeFromBuffer` must use the exact consumed size returned by `tryParse`, never `m_buffer.size()`.
- **NetBIOS mode** — expects 4-byte NBSS header (type=0x00 + 3-byte big-endian length).
- **FileAssembler READ correlation** — SMBv2 READ response has no file_id. Assembler tracks `m_last_read_file_id` from the preceding READ request, falling back to tree_id match.
- **`data_offset` interpretation** — BOTH SMBv1 and SMBv2 use absolute offset from the SMB header start. This is easy to get wrong and has caused bugs in both directions (treating as relative to data block, or relative to response struct). See `Smb2ReadResponse` (MS-SMB2 §2.2.21) and `Smb1ReadAndXResponse` (MS-CIFS §2.2.4.42.2). The code now uses `reinterpret_cast<const uint8_t*>(pkt.header()) + doff` consistently.
- **`Smb2ReadResponse` struct layout** — `data_offset` is `uint8_t` (1 byte), followed by `uint8_t reserved`. Do NOT change it to `uint16_t` — the struct size stays 17 either way, but the field alignment shifts, `reserved` disappears, and all subsequent fields read wrong values. The correct layout is verified by `static_assert(sizeof(Smb2ReadResponse) == 17)`.
- **No encryption support.** Encrypted packets are marked and skipped.
- **TRANSACT2/NT_TRANSACT** sub-commands parse the outer header but do not deeply parse sub-function parameters.
