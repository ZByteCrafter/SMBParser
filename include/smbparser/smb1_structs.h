#ifndef SMBPARSER_SMB1_STRUCTS_H
#define SMBPARSER_SMB1_STRUCTS_H

#include "types.h"

namespace smbparser {

PACKED_STRUCT_BEGIN

// SMBv1通用头 (32 bytes) — MS-CIFS Section 2.2.3.1
struct Smb1Header {
    uint8_t  protocol[4];    // \xFF"SMB"
    uint8_t  command;        // SMB_COM_xxx
    uint32_t status;         // NTSTATUS (4 bytes, LE)
    uint8_t  flags;
    uint16_t flags2;
    uint16_t pid_high;
    uint8_t  signature[8];
    uint16_t reserved;
    uint16_t tid;            // Tree ID
    uint16_t pid_low;
    uint16_t uid;            // User ID
    uint16_t mid;            // Multiplex ID
};

// SMB_COM_NEGOTIATE (0x72) Response — MS-CIFS Section 2.2.4.53.2
// Fixed param block: WordCount=17 (1 byte) + 17 words (34 bytes) = 35 bytes
struct Smb1NegotiateResponse {
    uint8_t  word_count;        // 17
    uint16_t dialect_index;
    uint8_t  security_mode;
    uint16_t max_mpx_count;
    uint16_t max_vc_count;
    uint32_t max_buffer_size;
    uint32_t max_raw_size;
    uint32_t session_key;
    uint32_t capabilities;
    uint32_t system_time_low;
    uint32_t system_time_high;
    uint16_t server_timezone;
    uint8_t  challenge_len;
    // Followed by: uint16_t byte_count, then challenge bytes, then domain_name (ASCIIZ)
};

// SMB_COM_NEGOTIATE (0x72) Request — MS-CIFS Section 2.2.4.52.1
// Only WordCount byte is fixed; rest is variable dialects
struct Smb1NegotiateRequest {
    uint8_t  word_count;
    // Followed by: uint16_t byte_count, then dialect strings
};

// SMB_COM_SESSION_SETUP_ANDX (0x73) Request — WordCount=13 (1 + 13*2 = 27)
struct Smb1SessionSetupAndXRequest {
    uint8_t  word_count;
    uint8_t  andx_command;
    uint8_t  andx_reserved;
    uint16_t andx_offset;
    uint16_t max_buffer_size;
    uint16_t max_mpx_count;
    uint16_t vc_number;
    uint32_t session_key;
    uint16_t security_blob_length;
    uint16_t case_sensitive_password_len;
    uint32_t reserved;
    uint32_t capabilities;
};

// SMB_COM_TREE_CONNECT_ANDX (0x75) — WordCount=4 req, WordCount=3 resp
struct Smb1TreeConnectAndXRequest {
    uint8_t  word_count;
    uint8_t  andx_command;
    uint8_t  andx_reserved;
    uint16_t andx_offset;
    uint16_t flags;
    uint16_t password_len;
};

struct Smb1TreeConnectAndXResponse {
    uint8_t  word_count;
    uint8_t  andx_command;
    uint8_t  andx_reserved;
    uint16_t andx_offset;
    uint16_t optional_support;
};

// SMB_COM_NT_CREATE_ANDX (0xA2) Response — WordCount=34 (1 + 34*2 = 69)
struct Smb1NtCreateAndXResponse {
    uint8_t  word_count;
    uint8_t  andx_command;
    uint8_t  andx_reserved;
    uint16_t andx_offset;
    uint8_t  oplock_level;
    uint16_t fid;
    uint32_t create_action;
    uint64_t creation_time;
    uint64_t last_access_time;
    uint64_t last_write_time;
    uint64_t change_time;
    uint32_t file_attributes;
    uint64_t allocation_size;
    uint64_t end_of_file;
    uint16_t resource_type;
    uint16_t status_flags;
    uint8_t  directory;
};

// SMB_COM_READ_ANDX (0x2E) — WordCount=12 req (1 + 12*2 = 25), WordCount=12 resp (1 + 12*2 = 25)
struct Smb1ReadAndXRequest {
    uint8_t  word_count;
    uint8_t  andx_command;
    uint8_t  andx_reserved;
    uint16_t andx_offset;
    uint16_t fid;
    uint32_t offset;
    uint16_t max_count;
    uint16_t min_count;
    uint32_t max_count_high;
    uint16_t remaining;
    uint32_t offset_high;
};

struct Smb1ReadAndXResponse {
    uint8_t  word_count;
    uint8_t  andx_command;
    uint8_t  andx_reserved;
    uint16_t andx_offset;
    uint16_t remaining;
    uint16_t data_compaction_mode;
    uint16_t reserved2;
    uint16_t data_length;
    uint16_t data_offset;
    uint32_t data_length_high;
    uint32_t reserved3;
    uint16_t reserved4;
};

// SMB_COM_WRITE_ANDX (0x2F) — WordCount=14 req, WordCount=6 resp
struct Smb1WriteAndXRequest {
    uint8_t  word_count;
    uint8_t  andx_command;
    uint8_t  andx_reserved;
    uint16_t andx_offset;
    uint16_t fid;
    uint32_t offset;
    uint32_t reserved;
    uint16_t write_mode;
    uint16_t remaining;
    uint16_t data_length_high;
    uint16_t data_length;
    uint16_t data_offset;
    uint32_t offset_high;
};

struct Smb1WriteAndXResponse {
    uint8_t  word_count;
    uint8_t  andx_command;
    uint8_t  andx_reserved;
    uint16_t andx_offset;
    uint16_t count;
    uint16_t remaining;
    uint16_t count_high;
    uint16_t reserved2;
};

// SMB_COM_CLOSE (0x04) — WordCount=3
struct Smb1CloseRequest {
    uint8_t  word_count;
    uint16_t fid;
    uint32_t last_write_time;
};

PACKED_STRUCT_END

} // namespace smbparser

#endif // SMBPARSER_SMB1_STRUCTS_H
