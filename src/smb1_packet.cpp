#include <smbparser/smb1_packet.h>
#include <cstring>

namespace smbparser {

SMBv1Packet::SMBv1Packet(const uint8_t* data, size_t length)
    : m_data(data), m_length(length)
{
    // 1. Minimum length check for header
    if (length < sizeof(Smb1Header)) {
        m_error = "too short for SMBv1 header";
        return;
    }

    // 2. Magic validation: \xFF"SMB"
    if (data[0] != 0xFF || data[1] != 'S' || data[2] != 'M' || data[3] != 'B') {
        m_error = "bad SMBv1 magic";
        return;
    }

    // 3. WordCount and ByteCount consistency
    size_t wc_offset = sizeof(Smb1Header);
    if (wc_offset >= length) {
        m_error = "missing WordCount";
        return;
    }
    uint8_t word_count = data[wc_offset];
    size_t param_end = wc_offset + 1 + static_cast<size_t>(word_count) * 2;

    if (param_end + 2 > length) {
        m_error = "param block truncated";
        return;
    }

    uint16_t byte_count = le16toh(*reinterpret_cast<const uint16_t*>(data + param_end));
    size_t data_end = param_end + 2 + byte_count;

    if (data_end > length) {
        m_error = "data block truncated";
        return;
    }

    // 4. All checks passed
    m_param_offset = wc_offset + 1;
    m_data_offset  = param_end + 2;
    m_data_size    = byte_count;
    m_valid        = true;
}

nlohmann::json SMBv1Packet::toJson() const {
    nlohmann::json j;
    j["protocol"] = "SMBv1";
    if (!m_valid) {
        j["valid"] = false;
        j["error"] = m_error;
        return j;
    }
    j["valid"] = true;
    const Smb1Header* hdr = header();
    j["command"] = smb1_command_to_string(hdr->command);
    j["command_code"] = hdr->command;
    j["status"] = ntstatus_to_string(le32toh(hdr->status));
    j["flags"] = hdr->flags;
    j["flags2"] = static_cast<int>(le16toh(hdr->flags2));
    j["pid"] = (static_cast<uint32_t>(le16toh(hdr->pid_high)) << 16) | le16toh(hdr->pid_low);
    j["tid"] = le16toh(hdr->tid);
    j["uid"] = le16toh(hdr->uid);
    j["mid"] = le16toh(hdr->mid);
    j["data_size"] = m_data_size;
    return j;
}

} // namespace smbparser
