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
    m_param_offset = wc_offset;
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

    nlohmann::json params;
    uint8_t cmd = hdr->command;

    switch (cmd) {
        case SMB_COM_NEGOTIATE:
            if (m_param_offset + sizeof(Smb1NegotiateResponse) <= m_length) {
                auto* nr = static_cast<const Smb1NegotiateResponse*>(paramBlock());
                params["dialect_index"] = le16toh(nr->dialect_index);
                params["security_mode"] = static_cast<int>(nr->security_mode);
                params["max_buffer_size"] = le32toh(nr->max_buffer_size);
                params["capabilities"] = le32toh(nr->capabilities);
                params["max_mpx_count"] = le16toh(nr->max_mpx_count);
                params["max_vc_count"] = le16toh(nr->max_vc_count);
            }
            break;
        case SMB_COM_NT_CREATE_ANDX:
            if (m_param_offset + sizeof(Smb1NtCreateAndXResponse) <= m_length) {
                auto* resp = static_cast<const Smb1NtCreateAndXResponse*>(paramBlock());
                params["fid"] = le16toh(resp->fid);
                params["oplock_level"] = static_cast<int>(resp->oplock_level);
                params["create_action"] = le32toh(resp->create_action);
                params["end_of_file"] = le64toh(resp->end_of_file);
                params["allocation_size"] = le64toh(resp->allocation_size);
            }
            break;
        case SMB_COM_READ_ANDX:
            if (m_param_offset + sizeof(Smb1ReadAndXResponse) <= m_length) {
                auto* resp = static_cast<const Smb1ReadAndXResponse*>(paramBlock());
                params["data_length"] = le16toh(resp->data_length);
                params["data_offset"] = le16toh(resp->data_offset);
                params["remaining"] = le16toh(resp->remaining);
            } else if (m_param_offset + sizeof(Smb1ReadAndXRequest) <= m_length) {
                auto* req = static_cast<const Smb1ReadAndXRequest*>(paramBlock());
                params["fid"] = le16toh(req->fid);
                params["max_count"] = le16toh(req->max_count);
                params["offset"] = le32toh(req->offset);
            }
            break;
        case SMB_COM_WRITE_ANDX:
            if (m_param_offset + sizeof(Smb1WriteAndXResponse) <= m_length) {
                auto* resp = static_cast<const Smb1WriteAndXResponse*>(paramBlock());
                params["count"] = le16toh(resp->count);
                params["remaining"] = le16toh(resp->remaining);
            } else if (m_param_offset + sizeof(Smb1WriteAndXRequest) <= m_length) {
                auto* req = static_cast<const Smb1WriteAndXRequest*>(paramBlock());
                params["fid"] = le16toh(req->fid);
                params["data_length"] = le16toh(req->data_length);
                params["offset"] = le32toh(req->offset);
            }
            break;
        case SMB_COM_CLOSE:
            if (m_param_offset + sizeof(Smb1CloseRequest) <= m_length) {
                auto* req = static_cast<const Smb1CloseRequest*>(paramBlock());
                params["fid"] = le16toh(req->fid);
            }
            break;
        case SMB_COM_SESSION_SETUP_ANDX:
            if (m_param_offset + sizeof(Smb1SessionSetupAndXRequest) <= m_length) {
                auto* req = static_cast<const Smb1SessionSetupAndXRequest*>(paramBlock());
                params["security_blob_length"] = le16toh(req->security_blob_length);
                params["capabilities"] = le32toh(req->capabilities);
            }
            break;
        case SMB_COM_TREE_CONNECT_ANDX:
            if (m_param_offset + sizeof(Smb1TreeConnectAndXResponse) <= m_length) {
                auto* resp = static_cast<const Smb1TreeConnectAndXResponse*>(paramBlock());
                params["optional_support"] = le16toh(resp->optional_support);
            }
            break;
    }
    if (!params.empty()) j["params"] = params;
    return j;
}

} // namespace smbparser
