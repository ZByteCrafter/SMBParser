#ifndef SMBPARSER_TYPES_H
#define SMBPARSER_TYPES_H

#include <cstdint>
#include <cstdio>
#include <string>

#if defined(_MSC_VER)
#  define PACKED_STRUCT_BEGIN __pragma(pack(push, 1))
#  define PACKED_STRUCT_END   __pragma(pack(pop))
#elif defined(__GNUC__) || defined(__clang__)
#  define PACKED_STRUCT_BEGIN _Pragma("pack(push, 1)")
#  define PACKED_STRUCT_END   _Pragma("pack(pop)")
#else
#  error "Unsupported compiler: need pack(push, 1) equivalent"
#endif

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define SMB_BIG_ENDIAN 1
#else
#  define SMB_BIG_ENDIAN 0
#endif

namespace smbparser {

#if SMB_BIG_ENDIAN
#  if defined(_MSC_VER)
#    include <cstdlib>
inline uint16_t smb_le16toh(uint16_t v) { return _byteswap_ushort(v); }
inline uint32_t smb_le32toh(uint32_t v) { return _byteswap_ulong(v); }
inline uint64_t smb_le64toh(uint64_t v) { return _byteswap_uint64(v); }
#  else
inline uint16_t smb_le16toh(uint16_t v) { return static_cast<uint16_t>((v >> 8) | (v << 8)); }
inline uint32_t smb_le32toh(uint32_t v) { return __builtin_bswap32(v); }
inline uint64_t smb_le64toh(uint64_t v) { return __builtin_bswap64(v); }
#  endif
#else
inline uint16_t smb_le16toh(uint16_t v) { return v; }
inline uint32_t smb_le32toh(uint32_t v) { return v; }
inline uint64_t smb_le64toh(uint64_t v) { return v; }
#endif

enum Smb1Command : uint8_t {
    SMB_COM_CREATE_DIRECTORY       = 0x00,
    SMB_COM_DELETE_DIRECTORY       = 0x01,
    SMB_COM_OPEN                   = 0x02,
    SMB_COM_CREATE                 = 0x03,
    SMB_COM_CLOSE                  = 0x04,
    SMB_COM_FLUSH                  = 0x05,
    SMB_COM_DELETE                 = 0x06,
    SMB_COM_RENAME                 = 0x07,
    SMB_COM_QUERY_INFORMATION      = 0x08,
    SMB_COM_SET_INFORMATION        = 0x09,
    SMB_COM_READ                   = 0x0A,
    SMB_COM_WRITE                  = 0x0B,
    SMB_COM_LOCK_BYTE_RANGE        = 0x0C,
    SMB_COM_UNLOCK_BYTE_RANGE      = 0x0D,
    SMB_COM_CREATE_TEMPORARY       = 0x0E,
    SMB_COM_CREATE_NEW             = 0x0F,
    SMB_COM_CHECK_DIRECTORY        = 0x10,
    SMB_COM_PROCESS_EXIT           = 0x11,
    SMB_COM_SEEK                   = 0x12,
    SMB_COM_LOCK_AND_READ          = 0x13,
    SMB_COM_WRITE_AND_UNLOCK       = 0x14,
    SMB_COM_READ_RAW               = 0x1A,
    SMB_COM_READ_MPX               = 0x1B,
    SMB_COM_READ_MPX_SECONDARY     = 0x1C,
    SMB_COM_WRITE_RAW              = 0x1D,
    SMB_COM_WRITE_MPX              = 0x1E,
    SMB_COM_WRITE_MPX_SECONDARY    = 0x1F,
    SMB_COM_WRITE_COMPLETE         = 0x20,
    SMB_COM_QUERY_SERVER           = 0x21,
    SMB_COM_SET_INFORMATION2       = 0x22,
    SMB_COM_QUERY_INFORMATION2     = 0x23,
    SMB_COM_LOCKING_ANDX           = 0x24,
    SMB_COM_TRANSACTION            = 0x25,
    SMB_COM_TRANSACTION_SECONDARY  = 0x26,
    SMB_COM_IOCTL                  = 0x27,
    SMB_COM_IOCTL_SECONDARY        = 0x28,
    SMB_COM_COPY                   = 0x29,
    SMB_COM_MOVE                   = 0x2A,
    SMB_COM_ECHO                   = 0x2B,
    SMB_COM_WRITE_AND_CLOSE        = 0x2C,
    SMB_COM_OPEN_ANDX              = 0x2D,
    SMB_COM_READ_ANDX              = 0x2E,
    SMB_COM_WRITE_ANDX             = 0x2F,
    SMB_COM_NEW_FILE_SIZE          = 0x30,
    SMB_COM_CLOSE_AND_TREE_DISC    = 0x31,
    SMB_COM_TRANSACTION2           = 0x32,
    SMB_COM_TRANSACTION2_SECONDARY = 0x33,
    SMB_COM_FIND_CLOSE2            = 0x34,
    SMB_COM_FIND_NOTIFY_CLOSE      = 0x35,
    SMB_COM_TREE_CONNECT           = 0x70,
    SMB_COM_TREE_DISCONNECT        = 0x71,
    SMB_COM_NEGOTIATE              = 0x72,
    SMB_COM_SESSION_SETUP_ANDX     = 0x73,
    SMB_COM_LOGOFF_ANDX            = 0x74,
    SMB_COM_TREE_CONNECT_ANDX      = 0x75,
    SMB_COM_QUERY_INFORMATION_DISK = 0x80,
    SMB_COM_SEARCH                 = 0x81,
    SMB_COM_FIND                   = 0x82,
    SMB_COM_FIND_UNIQUE            = 0x83,
    SMB_COM_FIND_CLOSE             = 0x84,
    SMB_COM_NT_TRANSACT            = 0xA0,
    SMB_COM_NT_TRANSACT_SECONDARY  = 0xA1,
    SMB_COM_NT_CREATE_ANDX         = 0xA2,
    SMB_COM_NT_CANCEL              = 0xA4,
    SMB_COM_NT_RENAME              = 0xA5,
    SMB_COM_OPEN_PRINT_FILE        = 0xC0,
    SMB_COM_WRITE_PRINT_FILE       = 0xC1,
    SMB_COM_CLOSE_PRINT_FILE       = 0xC2,
    SMB_COM_GET_PRINT_QUEUE        = 0xC3,
    SMB_COM_READ_BULK              = 0xD8,
    SMB_COM_WRITE_BULK             = 0xD9,
    SMB_COM_WRITE_BULK_DATA        = 0xDA,
};

enum Smb2Command : uint16_t {
    SMB2_NEGOTIATE       = 0x0000,
    SMB2_SESSION_SETUP   = 0x0001,
    SMB2_LOGOFF          = 0x0002,
    SMB2_TREE_CONNECT    = 0x0003,
    SMB2_TREE_DISCONNECT = 0x0004,
    SMB2_CREATE          = 0x0005,
    SMB2_CLOSE           = 0x0006,
    SMB2_FLUSH           = 0x0007,
    SMB2_READ            = 0x0008,
    SMB2_WRITE           = 0x0009,
    SMB2_LOCK            = 0x000A,
    SMB2_IOCTL           = 0x000B,
    SMB2_CANCEL          = 0x000C,
    SMB2_ECHO            = 0x000D,
    SMB2_QUERY_DIRECTORY = 0x000E,
    SMB2_CHANGE_NOTIFY   = 0x000F,
    SMB2_QUERY_INFO      = 0x0010,
    SMB2_SET_INFO        = 0x0011,
    SMB2_OPLOCK_BREAK    = 0x0012,
};

enum NtStatus : uint32_t {
    STATUS_SUCCESS                  = 0x00000000,
    STATUS_PENDING                  = 0x00000103,
    STATUS_NOTIFY_CLEANUP           = 0x0000010B,
    STATUS_NOTIFY_ENUM_DIR          = 0x0000010C,
    STATUS_BUFFER_OVERFLOW          = 0x80000005,
    STATUS_NO_MORE_FILES            = 0x80000006,
    STATUS_STOPPED_ON_SYMLINK       = 0x8000002D,
    STATUS_NOT_IMPLEMENTED          = 0xC0000002,
    STATUS_INVALID_HANDLE           = 0xC0000008,
    STATUS_INVALID_PARAMETER        = 0xC000000D,
    STATUS_NO_SUCH_FILE             = 0xC000000F,
    STATUS_INVALID_DEVICE_REQUEST   = 0xC0000010,
    STATUS_END_OF_FILE              = 0xC0000011,
    STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016,
    STATUS_ACCESS_DENIED            = 0xC0000022,
    STATUS_BUFFER_TOO_SMALL         = 0xC0000023,
    STATUS_OBJECT_NAME_NOT_FOUND    = 0xC0000034,
    STATUS_OBJECT_PATH_NOT_FOUND    = 0xC000003A,
    STATUS_SHARING_VIOLATION        = 0xC0000043,
    STATUS_LOGON_FAILURE            = 0xC000006D,
    STATUS_NOT_SUPPORTED            = 0xC00000BB,
    STATUS_BAD_NETWORK_NAME         = 0xC00000CC,
    STATUS_REQUEST_NOT_ACCEPTED     = 0xC00000D0,
    STATUS_NETWORK_NAME_DELETED     = 0xC00000C9,
    STATUS_FILE_DELETED             = 0xC00000C3,
    STATUS_FILE_CLOSED              = 0xC0000128,
    STATUS_INSUFF_SERVER_RESOURCES  = 0xC0000205,
    STATUS_USER_SESSION_DELETED     = 0xC0000203,
};

enum Smb2Dialect : uint16_t {
    SMB2_DIALECT_202      = 0x0202,
    SMB2_DIALECT_210      = 0x0210,
    SMB2_DIALECT_300      = 0x0300,
    SMB2_DIALECT_302      = 0x0302,
    SMB2_DIALECT_311      = 0x0311,
    SMB2_DIALECT_WILDCARD = 0x02FF,
};

inline std::string smb1_command_to_string(uint8_t cmd) {
    switch (static_cast<Smb1Command>(cmd)) {
    case SMB_COM_CREATE_DIRECTORY:       return "SMB_COM_CREATE_DIRECTORY";
    case SMB_COM_DELETE_DIRECTORY:       return "SMB_COM_DELETE_DIRECTORY";
    case SMB_COM_OPEN:                   return "SMB_COM_OPEN";
    case SMB_COM_CREATE:                 return "SMB_COM_CREATE";
    case SMB_COM_CLOSE:                  return "SMB_COM_CLOSE";
    case SMB_COM_FLUSH:                  return "SMB_COM_FLUSH";
    case SMB_COM_DELETE:                 return "SMB_COM_DELETE";
    case SMB_COM_RENAME:                 return "SMB_COM_RENAME";
    case SMB_COM_QUERY_INFORMATION:      return "SMB_COM_QUERY_INFORMATION";
    case SMB_COM_SET_INFORMATION:        return "SMB_COM_SET_INFORMATION";
    case SMB_COM_READ:                   return "SMB_COM_READ";
    case SMB_COM_WRITE:                  return "SMB_COM_WRITE";
    case SMB_COM_LOCK_BYTE_RANGE:        return "SMB_COM_LOCK_BYTE_RANGE";
    case SMB_COM_UNLOCK_BYTE_RANGE:      return "SMB_COM_UNLOCK_BYTE_RANGE";
    case SMB_COM_CREATE_TEMPORARY:       return "SMB_COM_CREATE_TEMPORARY";
    case SMB_COM_CREATE_NEW:             return "SMB_COM_CREATE_NEW";
    case SMB_COM_CHECK_DIRECTORY:        return "SMB_COM_CHECK_DIRECTORY";
    case SMB_COM_PROCESS_EXIT:           return "SMB_COM_PROCESS_EXIT";
    case SMB_COM_SEEK:                   return "SMB_COM_SEEK";
    case SMB_COM_LOCK_AND_READ:          return "SMB_COM_LOCK_AND_READ";
    case SMB_COM_WRITE_AND_UNLOCK:       return "SMB_COM_WRITE_AND_UNLOCK";
    case SMB_COM_READ_RAW:               return "SMB_COM_READ_RAW";
    case SMB_COM_READ_MPX:               return "SMB_COM_READ_MPX";
    case SMB_COM_READ_MPX_SECONDARY:     return "SMB_COM_READ_MPX_SECONDARY";
    case SMB_COM_WRITE_RAW:              return "SMB_COM_WRITE_RAW";
    case SMB_COM_WRITE_MPX:              return "SMB_COM_WRITE_MPX";
    case SMB_COM_WRITE_MPX_SECONDARY:    return "SMB_COM_WRITE_MPX_SECONDARY";
    case SMB_COM_WRITE_COMPLETE:         return "SMB_COM_WRITE_COMPLETE";
    case SMB_COM_QUERY_SERVER:           return "SMB_COM_QUERY_SERVER";
    case SMB_COM_SET_INFORMATION2:       return "SMB_COM_SET_INFORMATION2";
    case SMB_COM_QUERY_INFORMATION2:     return "SMB_COM_QUERY_INFORMATION2";
    case SMB_COM_LOCKING_ANDX:           return "SMB_COM_LOCKING_ANDX";
    case SMB_COM_TRANSACTION:            return "SMB_COM_TRANSACTION";
    case SMB_COM_TRANSACTION_SECONDARY:  return "SMB_COM_TRANSACTION_SECONDARY";
    case SMB_COM_IOCTL:                  return "SMB_COM_IOCTL";
    case SMB_COM_IOCTL_SECONDARY:        return "SMB_COM_IOCTL_SECONDARY";
    case SMB_COM_COPY:                   return "SMB_COM_COPY";
    case SMB_COM_MOVE:                   return "SMB_COM_MOVE";
    case SMB_COM_ECHO:                   return "SMB_COM_ECHO";
    case SMB_COM_WRITE_AND_CLOSE:        return "SMB_COM_WRITE_AND_CLOSE";
    case SMB_COM_OPEN_ANDX:              return "SMB_COM_OPEN_ANDX";
    case SMB_COM_READ_ANDX:              return "SMB_COM_READ_ANDX";
    case SMB_COM_WRITE_ANDX:             return "SMB_COM_WRITE_ANDX";
    case SMB_COM_NEW_FILE_SIZE:          return "SMB_COM_NEW_FILE_SIZE";
    case SMB_COM_CLOSE_AND_TREE_DISC:    return "SMB_COM_CLOSE_AND_TREE_DISC";
    case SMB_COM_TRANSACTION2:           return "SMB_COM_TRANSACTION2";
    case SMB_COM_TRANSACTION2_SECONDARY: return "SMB_COM_TRANSACTION2_SECONDARY";
    case SMB_COM_FIND_CLOSE2:            return "SMB_COM_FIND_CLOSE2";
    case SMB_COM_FIND_NOTIFY_CLOSE:      return "SMB_COM_FIND_NOTIFY_CLOSE";
    case SMB_COM_TREE_CONNECT:           return "SMB_COM_TREE_CONNECT";
    case SMB_COM_TREE_DISCONNECT:        return "SMB_COM_TREE_DISCONNECT";
    case SMB_COM_NEGOTIATE:              return "SMB_COM_NEGOTIATE";
    case SMB_COM_SESSION_SETUP_ANDX:     return "SMB_COM_SESSION_SETUP_ANDX";
    case SMB_COM_LOGOFF_ANDX:            return "SMB_COM_LOGOFF_ANDX";
    case SMB_COM_TREE_CONNECT_ANDX:      return "SMB_COM_TREE_CONNECT_ANDX";
    case SMB_COM_QUERY_INFORMATION_DISK: return "SMB_COM_QUERY_INFORMATION_DISK";
    case SMB_COM_SEARCH:                 return "SMB_COM_SEARCH";
    case SMB_COM_FIND:                   return "SMB_COM_FIND";
    case SMB_COM_FIND_UNIQUE:            return "SMB_COM_FIND_UNIQUE";
    case SMB_COM_FIND_CLOSE:             return "SMB_COM_FIND_CLOSE";
    case SMB_COM_NT_TRANSACT:            return "SMB_COM_NT_TRANSACT";
    case SMB_COM_NT_TRANSACT_SECONDARY:  return "SMB_COM_NT_TRANSACT_SECONDARY";
    case SMB_COM_NT_CREATE_ANDX:         return "SMB_COM_NT_CREATE_ANDX";
    case SMB_COM_NT_CANCEL:              return "SMB_COM_NT_CANCEL";
    case SMB_COM_NT_RENAME:              return "SMB_COM_NT_RENAME";
    case SMB_COM_OPEN_PRINT_FILE:        return "SMB_COM_OPEN_PRINT_FILE";
    case SMB_COM_WRITE_PRINT_FILE:       return "SMB_COM_WRITE_PRINT_FILE";
    case SMB_COM_CLOSE_PRINT_FILE:       return "SMB_COM_CLOSE_PRINT_FILE";
    case SMB_COM_GET_PRINT_QUEUE:        return "SMB_COM_GET_PRINT_QUEUE";
    case SMB_COM_READ_BULK:              return "SMB_COM_READ_BULK";
    case SMB_COM_WRITE_BULK:             return "SMB_COM_WRITE_BULK";
    case SMB_COM_WRITE_BULK_DATA:        return "SMB_COM_WRITE_BULK_DATA";
    default: {
        char buf[32];
        snprintf(buf, sizeof(buf), "UNKNOWN_0x%X", cmd);
        return std::string(buf);
    }
    }
}

inline std::string smb2_command_to_string(uint16_t cmd) {
    switch (static_cast<Smb2Command>(cmd)) {
    case SMB2_NEGOTIATE:       return "SMB2_NEGOTIATE";
    case SMB2_SESSION_SETUP:   return "SMB2_SESSION_SETUP";
    case SMB2_LOGOFF:          return "SMB2_LOGOFF";
    case SMB2_TREE_CONNECT:    return "SMB2_TREE_CONNECT";
    case SMB2_TREE_DISCONNECT: return "SMB2_TREE_DISCONNECT";
    case SMB2_CREATE:          return "SMB2_CREATE";
    case SMB2_CLOSE:           return "SMB2_CLOSE";
    case SMB2_FLUSH:           return "SMB2_FLUSH";
    case SMB2_READ:            return "SMB2_READ";
    case SMB2_WRITE:           return "SMB2_WRITE";
    case SMB2_LOCK:            return "SMB2_LOCK";
    case SMB2_IOCTL:           return "SMB2_IOCTL";
    case SMB2_CANCEL:          return "SMB2_CANCEL";
    case SMB2_ECHO:            return "SMB2_ECHO";
    case SMB2_QUERY_DIRECTORY: return "SMB2_QUERY_DIRECTORY";
    case SMB2_CHANGE_NOTIFY:   return "SMB2_CHANGE_NOTIFY";
    case SMB2_QUERY_INFO:      return "SMB2_QUERY_INFO";
    case SMB2_SET_INFO:        return "SMB2_SET_INFO";
    case SMB2_OPLOCK_BREAK:    return "SMB2_OPLOCK_BREAK";
    default: {
        char buf[32];
        snprintf(buf, sizeof(buf), "UNKNOWN_0x%X", cmd);
        return std::string(buf);
    }
    }
}

inline std::string ntstatus_to_string(uint32_t status) {
    switch (static_cast<NtStatus>(status)) {
    case STATUS_SUCCESS:                  return "STATUS_SUCCESS";
    case STATUS_PENDING:                  return "STATUS_PENDING";
    case STATUS_NOTIFY_CLEANUP:           return "STATUS_NOTIFY_CLEANUP";
    case STATUS_NOTIFY_ENUM_DIR:          return "STATUS_NOTIFY_ENUM_DIR";
    case STATUS_BUFFER_OVERFLOW:          return "STATUS_BUFFER_OVERFLOW";
    case STATUS_NO_MORE_FILES:            return "STATUS_NO_MORE_FILES";
    case STATUS_STOPPED_ON_SYMLINK:       return "STATUS_STOPPED_ON_SYMLINK";
    case STATUS_NOT_IMPLEMENTED:          return "STATUS_NOT_IMPLEMENTED";
    case STATUS_INVALID_HANDLE:           return "STATUS_INVALID_HANDLE";
    case STATUS_INVALID_PARAMETER:        return "STATUS_INVALID_PARAMETER";
    case STATUS_NO_SUCH_FILE:             return "STATUS_NO_SUCH_FILE";
    case STATUS_INVALID_DEVICE_REQUEST:   return "STATUS_INVALID_DEVICE_REQUEST";
    case STATUS_END_OF_FILE:              return "STATUS_END_OF_FILE";
    case STATUS_MORE_PROCESSING_REQUIRED: return "STATUS_MORE_PROCESSING_REQUIRED";
    case STATUS_ACCESS_DENIED:            return "STATUS_ACCESS_DENIED";
    case STATUS_BUFFER_TOO_SMALL:         return "STATUS_BUFFER_TOO_SMALL";
    case STATUS_OBJECT_NAME_NOT_FOUND:    return "STATUS_OBJECT_NAME_NOT_FOUND";
    case STATUS_OBJECT_PATH_NOT_FOUND:    return "STATUS_OBJECT_PATH_NOT_FOUND";
    case STATUS_SHARING_VIOLATION:        return "STATUS_SHARING_VIOLATION";
    case STATUS_LOGON_FAILURE:            return "STATUS_LOGON_FAILURE";
    case STATUS_NOT_SUPPORTED:            return "STATUS_NOT_SUPPORTED";
    case STATUS_BAD_NETWORK_NAME:         return "STATUS_BAD_NETWORK_NAME";
    case STATUS_REQUEST_NOT_ACCEPTED:     return "STATUS_REQUEST_NOT_ACCEPTED";
    case STATUS_NETWORK_NAME_DELETED:     return "STATUS_NETWORK_NAME_DELETED";
    case STATUS_FILE_DELETED:             return "STATUS_FILE_DELETED";
    case STATUS_FILE_CLOSED:              return "STATUS_FILE_CLOSED";
    case STATUS_INSUFF_SERVER_RESOURCES:  return "STATUS_INSUFF_SERVER_RESOURCES";
    case STATUS_USER_SESSION_DELETED:     return "STATUS_USER_SESSION_DELETED";
    default: {
        char buf[32];
        snprintf(buf, sizeof(buf), "NTSTATUS_0x%X", status);
        return std::string(buf);
    }
    }
}

inline std::string smb2_dialect_to_string(uint16_t dialect) {
    switch (static_cast<Smb2Dialect>(dialect)) {
    case SMB2_DIALECT_202:      return "2.0.2";
    case SMB2_DIALECT_210:      return "2.1";
    case SMB2_DIALECT_300:      return "3.0";
    case SMB2_DIALECT_302:      return "3.0.2";
    case SMB2_DIALECT_311:      return "3.1.1";
    case SMB2_DIALECT_WILDCARD: return "WILDCARD";
    default: {
        char buf[32];
        snprintf(buf, sizeof(buf), "UNKNOWN_0x%X", dialect);
        return std::string(buf);
    }
    }
}

} // namespace smbparser

#endif // SMBPARSER_TYPES_H
