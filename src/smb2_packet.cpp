#include <smbparser/smb2_packet.h>
#include <smbparser/types.h>
#include <cstring>
#include <cstdio>

namespace smbparser {

SMBv2Packet::SMBv2Packet(const uint8_t* data, size_t length)
    : m_data(data), m_length(length)
{
    if (length < sizeof(Smb2Header)) {
        m_error = "too short for SMBv2 header";
        return;
    }
    if (data[0] != 0xFE || data[1] != 'S' || data[2] != 'M' || data[3] != 'B') {
        m_error = "bad SMBv2 magic";
        return;
    }
    const Smb2Header* hdr = reinterpret_cast<const Smb2Header*>(data);
    if (smb_le16toh(hdr->structure_size) != 64) {
        m_error = "invalid structure_size in SMBv2 header";
        return;
    }
    m_valid = true;
}

nlohmann::json SMBv2Packet::toJson() const {
    nlohmann::json j;
    j["protocol"] = "SMBv2";
    if (!m_valid) {
        j["valid"] = false;
        j["error"] = m_error;
        return j;
    }
    j["valid"] = true;
    const Smb2Header* hdr = header();
    j["command"] = smb2_command_to_string(smb_le16toh(hdr->command));
    j["command_code"] = smb_le16toh(hdr->command);
    j["status"] = ntstatus_to_string(smb_le32toh(hdr->status));
    j["message_id"] = smb_le64toh(hdr->message_id);
    j["session_id"] = smb_le64toh(hdr->session_id);
    j["tree_id"] = smb_le32toh(hdr->tree_id);
    j["credit_request"] = smb_le16toh(hdr->credit_request);
    j["credit_charge"] = smb_le16toh(hdr->credit_charge);
    j["flags"] = smb_le32toh(hdr->flags);
    j["has_next"] = hasNextCommand();
    j["data_size"] = commandParamsSize();

    // Command-specific params
    nlohmann::json params;
    uint16_t cmd = smb_le16toh(hdr->command);
    size_t psize = commandParamsSize();

    if (cmd == SMB2_NEGOTIATE && psize >= sizeof(Smb2NegotiateResponse)) {
        auto* nr = static_cast<const Smb2NegotiateResponse*>(commandParams());
        params["dialect_revision"] = smb2_dialect_to_string(smb_le16toh(nr->dialect_revision));
        params["capabilities"] = smb_le32toh(nr->capabilities);
        params["max_read_size"] = smb_le32toh(nr->max_read_size);
        params["max_write_size"] = smb_le32toh(nr->max_write_size);
        char guid[33];
        for (int i = 0; i < 16; i++) snprintf(guid + i*2, 3, "%02X", nr->server_guid[i]);
        params["server_guid"] = guid;
    }
    else if (cmd == SMB2_CREATE && psize >= sizeof(Smb2CreateResponse)) {
        auto* cr = static_cast<const Smb2CreateResponse*>(commandParams());
        if (smb_le16toh(cr->structure_size) == 89) {
            char fid[33];
            for (int i = 0; i < 16; i++) snprintf(fid + i*2, 3, "%02X", cr->file_id[i]);
            params["file_id"] = fid;
            params["end_of_file"] = smb_le64toh(cr->end_of_file);
            params["allocation_size"] = smb_le64toh(cr->allocation_size);
            params["oplock_level"] = cr->oplock_level;
            params["create_action"] = smb_le32toh(cr->create_action);
        }
    }
    else if (cmd == SMB2_READ && psize >= sizeof(Smb2ReadResponse)) {
        auto* rr = static_cast<const Smb2ReadResponse*>(commandParams());
        if (smb_le16toh(rr->structure_size) == 17) {
            params["data_length"] = smb_le32toh(rr->data_length);
            params["data_offset"] = rr->data_offset;
            params["data_remaining"] = smb_le32toh(rr->data_remaining);
        }
    }
    else if (cmd == SMB2_WRITE && psize >= sizeof(Smb2WriteResponse)) {
        auto* wr = static_cast<const Smb2WriteResponse*>(commandParams());
        uint16_t ss = smb_le16toh(wr->structure_size);
        if (ss == 49 && psize >= sizeof(Smb2WriteRequest)) {
            // WRITE Request (structure_size == 49)
            auto* req = static_cast<const Smb2WriteRequest*>(commandParams());
            params["length"] = smb_le32toh(req->length);
            params["offset"] = smb_le64toh(req->offset);
            char fid[33];
            for (int i = 0; i < 16; i++) snprintf(fid + i*2, 3, "%02X", req->file_id[i]);
            params["file_id"] = fid;
        }
        else if (ss == 17) {
            // WRITE Response (structure_size == 17)
            params["count"] = smb_le32toh(wr->count);
            params["remaining"] = smb_le32toh(wr->remaining);
        }
    }
    else if (cmd == SMB2_CLOSE && psize >= sizeof(Smb2CloseResponse)) {
        auto* cr = static_cast<const Smb2CloseResponse*>(commandParams());
        params["end_of_file"] = smb_le64toh(cr->end_of_file);
    }
    if (!params.empty()) j["params"] = params;

    return j;
}

} // namespace smbparser
