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

// SMB_COM_TRANSACTION (0x25) — WordCount=14+SetupCount
struct Smb1TransactionRequest {
    uint8_t  word_count; uint16_t total_param_count; uint16_t total_data_count;
    uint16_t max_param_count; uint16_t max_data_count; uint8_t max_setup_count;
    uint8_t  reserved; uint16_t flags; uint32_t timeout; uint16_t reserved2;
    uint16_t param_count; uint16_t param_offset; uint16_t data_count;
    uint16_t data_offset; uint8_t setup_count; uint8_t reserved3;
};

// SMB_COM_TRANSACTION2 (0x32) — WordCount=14+SetupCount
struct Smb1Transaction2Request {
    uint8_t  word_count; uint16_t total_param_count; uint16_t total_data_count;
    uint16_t max_param_count; uint16_t max_data_count; uint8_t max_setup_count;
    uint8_t  reserved; uint16_t flags; uint32_t timeout; uint16_t reserved2;
    uint16_t param_count; uint16_t param_offset; uint16_t data_count;
    uint16_t data_offset; uint8_t setup_count; uint8_t reserved3;
};

// SMB_COM_NT_TRANSACT (0xA0) — varies
struct Smb1NtTransactRequest {
    uint8_t  word_count; uint8_t max_setup_count; uint16_t reserved;
    uint32_t total_param_count; uint32_t total_data_count;
    uint32_t max_param_count; uint32_t max_data_count;
    uint32_t param_count; uint32_t param_offset;
    uint32_t data_count; uint32_t data_offset;
    uint8_t  setup_count; uint16_t function;
};

// SMB_COM_ECHO (0x2B) — WordCount=1
struct Smb1EchoRequest {
    uint8_t  word_count; uint16_t echo_count;
};

// SMB_COM_LOGOFF_ANDX (0x74) — WordCount=2
struct Smb1LogoffAndXRequest {
    uint8_t  word_count; uint8_t andx_command; uint8_t andx_reserved; uint16_t andx_offset;
};

// SMB_COM_LOCKING_ANDX (0x24) — WordCount=8
struct Smb1LockingAndXRequest {
    uint8_t  word_count; uint8_t andx_command; uint8_t andx_reserved; uint16_t andx_offset;
    uint16_t fid; uint8_t lock_type; uint8_t oplock_level; uint32_t timeout;
    uint16_t number_of_unlocks; uint16_t number_of_locks;
};

// SMB_COM_OPEN_ANDX (0x2D) Response — WordCount=15
struct Smb1OpenAndXResponse {
    uint8_t  word_count; uint8_t andx_command; uint8_t andx_reserved; uint16_t andx_offset;
    uint16_t fid; uint32_t file_attributes; uint64_t last_write_time;
    uint32_t data_size; uint16_t granted_access; uint16_t resource_type;
    uint16_t status_flags; uint8_t directory;
};

// SMB_COM_QUERY_INFORMATION (0x08) Response — WordCount=10
struct Smb1QueryInformationResponse {
    uint8_t  word_count; uint16_t file_attributes; uint32_t last_write_time;
    uint32_t data_size; uint16_t reserved[5];
};

// SMB_COM_SET_INFORMATION (0x09) Request — WordCount=8
struct Smb1SetInformationRequest {
    uint8_t  word_count; uint16_t file_attributes; uint32_t last_write_time;
    uint16_t reserved[5];
};

// SMB_COM_DELETE (0x06) Request — WordCount=1
struct Smb1DeleteRequest {
    uint8_t  word_count; uint16_t search_attributes;
};

// SMB_COM_RENAME (0x07) Request — WordCount=1
struct Smb1RenameRequest {
    uint8_t  word_count; uint16_t search_attributes;
};

// SMB_COM_FLUSH (0x05) Request — WordCount=1
struct Smb1FlushRequest {
    uint8_t  word_count; uint16_t fid;
};

// SMB_COM_IOCTL (0x27) Request — WordCount=4
struct Smb1IoctlRequest {
    uint8_t  word_count; uint16_t fid; uint32_t category; uint32_t function;
};

// SMB_COM_QUERY_INFORMATION2 (0x23) — WordCount=1
struct Smb1QueryInformation2Request {
    uint8_t  word_count; uint16_t fid;
};

// SMB_COM_SET_INFORMATION2 (0x22) — WordCount=7
struct Smb1SetInformation2Request {
    uint8_t  word_count; uint16_t fid; uint32_t creation_time;
    uint32_t last_access_time; uint32_t last_write_time;
};

// SMB_COM_WRITE_AND_CLOSE (0x2C) — WordCount=6
struct Smb1WriteAndCloseRequest {
    uint8_t  word_count; uint16_t fid; uint32_t offset; uint32_t timeout;
    uint16_t write_mode; uint16_t remaining; uint16_t data_length_high;
    uint16_t data_length; uint16_t data_offset; uint32_t offset_high;
};

// SMB_COM_READ_RAW (0x1A) — WordCount=4
struct Smb1ReadRawRequest {
    uint8_t  word_count; uint16_t fid; uint32_t offset; uint16_t max_count;
    uint16_t min_count; uint32_t timeout; uint16_t reserved;
};

// SMB_COM_WRITE_RAW (0x1D) — WordCount=6
struct Smb1WriteRawRequest {
    uint8_t  word_count; uint16_t fid; uint32_t total_bytes; uint16_t reserved;
    uint32_t offset; uint32_t timeout; uint16_t write_mode; uint16_t remaining;
    uint16_t data_length; uint16_t data_offset;
};

// SMB_COM_READ_MPX (0x1B) — WordCount=4
struct Smb1ReadMpxRequest {
    uint8_t  word_count; uint16_t fid; uint32_t offset; uint16_t max_count;
    uint16_t min_count; uint32_t timeout; uint16_t reserved;
};

// SMB_COM_WRITE_MPX (0x1E) — WordCount=6
struct Smb1WriteMpxRequest {
    uint8_t  word_count; uint16_t fid; uint32_t total_bytes; uint16_t reserved;
    uint32_t offset; uint32_t timeout; uint16_t write_mode; uint16_t remaining;
    uint16_t data_length; uint16_t data_offset;
};

PACKED_STRUCT_END

} // namespace smbparser

#endif // SMBPARSER_SMB1_STRUCTS_H
