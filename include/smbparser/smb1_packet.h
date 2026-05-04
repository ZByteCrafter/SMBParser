#ifndef SMBPARSER_SMB1_PACKET_H
#define SMBPARSER_SMB1_PACKET_H

#include "smb1_structs.h"
#include "types.h"
#include <nlohmann/json.hpp>
#include <string>
#include <cstdint>
#include <cstddef>

namespace smbparser {

class SMBv1Packet {
public:
    explicit SMBv1Packet(const uint8_t* data, size_t length);

    bool isValid() const { return m_valid; }
    const std::string& errorMessage() const { return m_error; }

    const Smb1Header* header() const {
        return reinterpret_cast<const Smb1Header*>(m_data);
    }
    uint8_t command() const { return header()->command; }
    uint32_t status() const { return smb_le32toh(header()->status); }
    const void* paramBlock() const { return m_data + m_param_offset; }
    const uint8_t* dataBlock() const { return m_data + m_data_offset; }
    size_t dataBlockSize() const { return m_data_size; }

    nlohmann::json toJson() const;

private:
    const uint8_t* m_data;
    size_t      m_length;
    bool        m_valid = false;
    std::string m_error;
    size_t      m_param_offset = 0;
    size_t      m_data_offset = 0;
    size_t      m_data_size = 0;
};

} // namespace smbparser

#endif
