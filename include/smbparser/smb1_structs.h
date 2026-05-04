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

PACKED_STRUCT_END

} // namespace smbparser

#endif // SMBPARSER_SMB1_STRUCTS_H
