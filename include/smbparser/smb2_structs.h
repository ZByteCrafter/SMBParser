#ifndef SMBPARSER_SMB2_STRUCTS_H
#define SMBPARSER_SMB2_STRUCTS_H

#include "types.h"

namespace smbparser {

PACKED_STRUCT_BEGIN

struct Smb2Header {
    uint8_t  protocol[4];
    uint16_t structure_size;
    uint16_t credit_charge;
    uint32_t status;
    uint16_t command;
    uint16_t credit_request;
    uint32_t flags;
    uint32_t next_command;
    uint64_t message_id;
    uint32_t reserved;
    uint32_t tree_id;
    uint64_t session_id;
    uint8_t  signature[16];
};

struct Smb2NegotiateResponse {
    uint16_t structure_size;
    uint16_t security_mode;
    uint16_t dialect_revision;
    uint16_t negotiate_context_count;
    uint8_t  server_guid[16];
    uint32_t capabilities;
    uint32_t max_transact_size;
    uint32_t max_read_size;
    uint32_t max_write_size;
    uint64_t system_time;
    uint64_t server_start_time;
    uint16_t security_buffer_offset;
    uint16_t security_buffer_length;
    uint32_t negotiate_context_offset;
};

struct Smb2NegotiateRequest {
    uint16_t structure_size;
    uint16_t dialect_count;
    uint16_t security_mode;
    uint16_t reserved;
    uint32_t capabilities;
    uint8_t  client_guid[16];
    uint32_t negotiate_context_offset;
    uint16_t negotiate_context_count;
    uint16_t reserved2;
};

// SMB2 SESSION_SETUP
struct Smb2SessionSetupRequest {
    uint16_t structure_size;
    uint8_t  flags;
    uint8_t  security_mode;
    uint32_t capabilities;
    uint32_t channel;
    uint16_t security_buffer_offset;
    uint16_t security_buffer_length;
    uint64_t previous_session_id;
};

struct Smb2SessionSetupResponse {
    uint16_t structure_size;
    uint16_t session_flags;
    uint16_t security_buffer_offset;
    uint16_t security_buffer_length;
};

// SMB2 TREE_CONNECT
struct Smb2TreeConnectRequest {
    uint16_t structure_size;
    uint16_t reserved;
    uint16_t path_offset;
    uint16_t path_length;
};

struct Smb2TreeConnectResponse {
    uint16_t structure_size;
    uint8_t  share_type;
    uint8_t  reserved;
    uint32_t share_flags;
    uint32_t share_capabilities;
    uint32_t maximal_access;
};

// SMB2 CREATE
struct Smb2CreateRequest {
    uint16_t structure_size;
    uint8_t  security_flags;
    uint8_t  requested_oplock_level;
    uint32_t impersonation_level;
    uint64_t create_flags;
    uint64_t reserved;
    uint32_t desired_access;
    uint32_t file_attributes;
    uint32_t share_access;
    uint32_t create_disposition;
    uint32_t create_options;
    uint16_t name_offset;
    uint16_t name_length;
    uint32_t create_contexts_offset;
    uint32_t create_contexts_length;
};

struct Smb2CreateResponse {
    uint16_t structure_size;
    uint8_t  oplock_level;
    uint8_t  flags;
    uint32_t create_action;
    uint64_t creation_time;
    uint64_t last_access_time;
    uint64_t last_write_time;
    uint64_t change_time;
    uint64_t allocation_size;
    uint64_t end_of_file;
    uint32_t file_attributes;
    uint32_t reserved2;
    uint8_t  file_id[16];
    uint32_t create_contexts_offset;
    uint32_t create_contexts_length;
    uint8_t  buffer[1];
};

// SMB2 READ
struct Smb2ReadRequest {
    uint16_t structure_size;
    uint8_t  padding;
    uint8_t  reserved;
    uint32_t length;
    uint64_t offset;
    uint8_t  file_id[16];
    uint32_t min_count;
    uint32_t channel;
    uint32_t remaining_bytes;
    uint16_t read_channel_info_offset;
    uint16_t read_channel_info_length;
};

struct Smb2ReadResponse {
    uint16_t structure_size;
    uint16_t data_offset;
    uint32_t data_length;
    uint32_t data_remaining;
    uint32_t reserved2;
    uint8_t  buffer[1];
};

// SMB2 WRITE
struct Smb2WriteRequest {
    uint16_t structure_size;
    uint16_t data_offset;
    uint32_t length;
    uint64_t offset;
    uint8_t  file_id[16];
    uint32_t channel;
    uint32_t remaining_bytes;
    uint16_t write_channel_info_offset;
    uint16_t write_channel_info_length;
    uint32_t flags;
};

struct Smb2WriteResponse {
    uint16_t structure_size;
    uint16_t reserved;
    uint32_t count;
    uint32_t remaining;
    uint16_t write_channel_info_offset;
    uint16_t write_channel_info_length;
};

// SMB2 CLOSE
struct Smb2CloseRequest {
    uint16_t structure_size;
    uint16_t flags;
    uint32_t reserved;
    uint8_t  file_id[16];
};

struct Smb2CloseResponse {
    uint16_t structure_size;
    uint16_t flags;
    uint32_t reserved;
    uint64_t creation_time;
    uint64_t last_access_time;
    uint64_t last_write_time;
    uint64_t change_time;
    uint64_t allocation_size;
    uint64_t end_of_file;
    uint32_t file_attributes;
};

// Simpler request/response structs
struct Smb2LogoffRequest { uint16_t structure_size; uint16_t reserved; };
struct Smb2LogoffResponse { uint16_t structure_size; uint16_t reserved; };
struct Smb2TreeDisconnectRequest { uint16_t structure_size; uint16_t reserved; };
struct Smb2TreeDisconnectResponse { uint16_t structure_size; uint16_t reserved; };

struct Smb2FlushRequest {
    uint16_t structure_size; uint16_t reserved1; uint32_t reserved2; uint8_t file_id[16];
};
struct Smb2FlushResponse { uint16_t structure_size; uint16_t reserved; };

struct Smb2LockElement { uint64_t offset; uint64_t length; uint32_t flags; uint32_t reserved; };
struct Smb2LockRequest {
    uint16_t structure_size; uint16_t lock_count; uint32_t lock_sequence; uint8_t file_id[16];
};
struct Smb2LockResponse { uint16_t structure_size; uint16_t reserved; };

struct Smb2IoctlRequest {
    uint16_t structure_size; uint16_t reserved; uint32_t ctl_code; uint8_t file_id[16];
    uint32_t input_offset; uint32_t input_count; uint32_t max_input_response;
    uint32_t output_offset; uint32_t output_count; uint32_t max_output_response;
    uint32_t flags; uint32_t reserved2;
};
struct Smb2IoctlResponse {
    uint16_t structure_size; uint16_t reserved; uint32_t ctl_code; uint8_t file_id[16];
    uint32_t input_offset; uint32_t input_count; uint32_t output_offset;
    uint32_t output_count; uint32_t flags; uint32_t reserved2;
};

struct Smb2CancelRequest { uint16_t structure_size; uint16_t reserved; };
struct Smb2EchoRequest { uint16_t structure_size; uint16_t reserved; };
struct Smb2EchoResponse { uint16_t structure_size; uint16_t reserved; };

struct Smb2QueryDirectoryRequest {
    uint16_t structure_size; uint8_t file_info_class; uint8_t flags; uint32_t file_index;
    uint8_t file_id[16]; uint16_t file_name_offset; uint16_t file_name_length;
    uint32_t output_buffer_length;
};
struct Smb2QueryDirectoryResponse {
    uint16_t structure_size; uint16_t output_buffer_offset; uint32_t output_buffer_length;
};

struct Smb2ChangeNotifyRequest {
    uint16_t structure_size; uint16_t flags; uint32_t output_buffer_length;
    uint8_t file_id[16]; uint32_t completion_filter; uint32_t reserved;
};
struct Smb2ChangeNotifyResponse {
    uint16_t structure_size; uint16_t output_buffer_offset; uint32_t output_buffer_length;
};

struct Smb2QueryInfoRequest {
    uint16_t structure_size; uint8_t info_type; uint8_t file_info_class;
    uint32_t output_buffer_length; uint16_t input_buffer_offset; uint16_t reserved;
    uint32_t input_buffer_length; uint32_t additional_information; uint32_t flags; uint8_t file_id[16];
};
struct Smb2QueryInfoResponse {
    uint16_t structure_size; uint16_t output_buffer_offset; uint32_t output_buffer_length;
};

struct Smb2SetInfoRequest {
    uint16_t structure_size; uint8_t info_type; uint8_t file_info_class;
    uint32_t buffer_length; uint16_t buffer_offset; uint16_t reserved;
    uint32_t additional_information; uint8_t file_id[16];
};
struct Smb2SetInfoResponse { uint16_t structure_size; };

struct Smb2OplockBreakNotification {
    uint16_t structure_size; uint8_t oplock_level; uint8_t reserved;
    uint32_t reserved2; uint8_t file_id[16];
};
struct Smb2OplockBreakResponse {
    uint16_t structure_size; uint8_t oplock_level; uint8_t reserved;
    uint32_t reserved2; uint8_t file_id[16];
};

PACKED_STRUCT_END

} // namespace smbparser

#endif
