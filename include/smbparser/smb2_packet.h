#ifndef SMBPARSER_SMB2_PACKET_H
#define SMBPARSER_SMB2_PACKET_H

#include "smb2_structs.h"
#include "types.h"
#include <nlohmann/json.hpp>
#include <string>
#include <cstdint>
#include <cstddef>

namespace smbparser {

class SMBv2Packet {
public:
    explicit SMBv2Packet(const uint8_t* data, size_t length);

    bool isValid() const { return m_valid; }
    const std::string& errorMessage() const { return m_error; }

    const Smb2Header* header() const {
        return reinterpret_cast<const Smb2Header*>(m_data);
    }
    uint16_t command() const { return smb_le16toh(header()->command); }
    uint32_t status() const { return smb_le32toh(header()->status); }
    uint64_t messageId() const { return smb_le64toh(header()->message_id); }
    uint64_t sessionId() const { return smb_le64toh(header()->session_id); }
    uint32_t treeId() const { return smb_le32toh(header()->tree_id); }

    const void* commandParams() const { return m_data + sizeof(Smb2Header); }
    size_t commandParamsSize() const {
        if (m_length <= sizeof(Smb2Header)) return 0;
        return m_length - sizeof(Smb2Header);
    }

    bool hasNextCommand() const { return smb_le32toh(header()->next_command) != 0; }
    size_t nextCommandOffset() const { return smb_le32toh(header()->next_command); }

    nlohmann::json toJson() const;

private:
    const uint8_t* m_data;
    size_t      m_length;
    bool        m_valid = false;
    std::string m_error;
};

} // namespace smbparser

#endif
