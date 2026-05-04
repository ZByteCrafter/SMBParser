#include <smbparser/file_assembler.h>
#include <algorithm>

namespace smbparser {

void FileAssembler::appendData(const std::string& key, const uint8_t* data, size_t len) {
    auto& info = m_files[key];
    info.data.insert(info.data.end(), data, data + len);
    info.bytes_read += len;
}

void FileAssembler::ensureFileEntry(const std::string& key) {
    if (m_files.find(key) == m_files.end()) {
        m_files[key] = FileInfo{};
    }
}

void FileAssembler::processV2Message(const SMBv2Packet& pkt) {
    if (!pkt.isValid()) return;

    uint16_t cmd = pkt.command();
    size_t psize = pkt.commandParamsSize();
    const uint8_t* params = static_cast<const uint8_t*>(pkt.commandParams());
    uint32_t tree_id = pkt.treeId();

    if (psize < 2) return;

    uint16_t structure_size = le16toh(*reinterpret_cast<const uint16_t*>(params));

    switch (cmd) {
    case SMB2_TREE_CONNECT:
        if (structure_size == 9 && psize >= sizeof(Smb2TreeConnectRequest)) {
            auto* req = reinterpret_cast<const Smb2TreeConnectRequest*>(params);
            uint16_t poff = le16toh(req->path_offset);
            uint16_t plen = le16toh(req->path_length);
            if (poff + plen <= psize) {
                const char* path = reinterpret_cast<const char*>(params) + poff;
                m_tree_map[tree_id] = std::string(path, plen);
            }
        }
        break;

    case SMB2_CREATE:
        if (structure_size == 89 && psize >= sizeof(Smb2CreateResponse)) {
            auto* cr = reinterpret_cast<const Smb2CreateResponse*>(params);
            char fid_hex[33];
            for (int i = 0; i < 16; i++)
                snprintf(fid_hex + i * 2, 3, "%02X", cr->file_id[i]);
            std::string fid_str(fid_hex);
            std::string key = makeFileKeyV2(tree_id, fid_str);
            m_fileid_filename[fid_str] = key;
            ensureFileEntry(key);
            FileInfo& info = m_files[key];
            info.tree_id = tree_id;
            info.file_id_hex = fid_str;
            info.file_size = le64toh(cr->end_of_file);
            info.protocol = "SMBv2";

            std::map<uint32_t, std::string>::const_iterator sit = m_tree_map.find(tree_id);
            if (sit != m_tree_map.end())
                info.share_path = sit->second;
        }
        break;

    case SMB2_READ:
        if (psize >= sizeof(Smb2ReadRequest) && structure_size == 49) {
            auto* rr = reinterpret_cast<const Smb2ReadRequest*>(params);
            char fid_hex[33];
            for (int i = 0; i < 16; i++)
                snprintf(fid_hex + i * 2, 3, "%02X", rr->file_id[i]);
            m_last_read_file_id = fid_hex;
            m_last_read_tree_id = tree_id;
        }
        else if (psize >= sizeof(Smb2ReadResponse) && structure_size == 17) {
            auto* rr = reinterpret_cast<const Smb2ReadResponse*>(params);
            uint32_t dlen = le32toh(rr->data_length);
            uint8_t doff = rr->data_offset;
            if (dlen > 0 && static_cast<size_t>(doff) + dlen <= psize) {
                const uint8_t* data = params + doff;
                std::string key;
                // try file_id from last READ request
                if (!m_last_read_file_id.empty()) {
                    std::map<std::string, std::string>::const_iterator it =
                        m_fileid_filename.find(m_last_read_file_id);
                    if (it != m_fileid_filename.end())
                        key = it->second;
                    m_last_read_file_id.clear();
                }
                // fallback: match by tree_id
                if (key.empty()) {
                    for (std::map<std::string, FileInfo>::iterator it = m_files.begin();
                         it != m_files.end(); ++it) {
                        if (it->second.tree_id == tree_id && !it->second.is_complete) {
                            key = it->first;
                            break;
                        }
                    }
                }
                // fallback: any incomplete file
                if (key.empty()) {
                    for (std::map<std::string, FileInfo>::iterator it = m_files.begin();
                         it != m_files.end(); ++it) {
                        if (!it->second.is_complete) {
                            key = it->first;
                            break;
                        }
                    }
                }
                // anonymous
                if (key.empty()) {
                    key = makeFileKeyV2(tree_id, "ANONYMOUS");
                    ensureFileEntry(key);
                    m_files[key].protocol = "SMBv2";
                    m_files[key].tree_id = tree_id;
                }
                appendData(key, data, dlen);
            }
        }
        break;

    case SMB2_WRITE:
        if (psize >= sizeof(Smb2WriteRequest) && structure_size == 49) {
            auto* wr = reinterpret_cast<const Smb2WriteRequest*>(params);
            uint32_t dlen = le32toh(wr->length);
            uint16_t doff = le16toh(wr->data_offset);
            char fid_hex[33];
            for (int i = 0; i < 16; i++)
                snprintf(fid_hex + i * 2, 3, "%02X", wr->file_id[i]);
            std::string fid_str(fid_hex);
            std::string key = makeFileKeyV2(tree_id, fid_str);

            std::map<std::string, std::string>::const_iterator fit =
                m_fileid_filename.find(fid_str);
            if (fit != m_fileid_filename.end()) {
                key = fit->second;
            } else {
                ensureFileEntry(key);
                m_files[key].file_id_hex = fid_str;
                m_files[key].tree_id = tree_id;
                m_files[key].protocol = "SMBv2";
            }

            if (dlen > 0 && static_cast<size_t>(doff) + dlen <= psize) {
                const uint8_t* data = params + doff;
                appendData(key, data, dlen);
            }
        }
        break;

    case SMB2_CLOSE:
        if (psize >= sizeof(Smb2CloseRequest) && structure_size == 24) {
            auto* cr = reinterpret_cast<const Smb2CloseRequest*>(params);
            char fid_hex[33];
            for (int i = 0; i < 16; i++)
                snprintf(fid_hex + i * 2, 3, "%02X", cr->file_id[i]);
            std::string fid_str(fid_hex);
            std::string key = makeFileKeyV2(tree_id, fid_str);

            std::map<std::string, std::string>::const_iterator fit =
                m_fileid_filename.find(fid_str);
            if (fit != m_fileid_filename.end())
                key = fit->second;

            ensureFileEntry(key);
            m_files[key].file_id_hex = fid_str;
            m_files[key].tree_id = tree_id;
            m_files[key].protocol = "SMBv2";
            m_files[key].is_complete = true;
        }
        else if (psize >= sizeof(Smb2CloseResponse) && structure_size == 60) {
            for (std::map<std::string, FileInfo>::iterator it = m_files.begin();
                 it != m_files.end(); ++it) {
                if (it->second.tree_id == tree_id && !it->second.is_complete) {
                    it->second.is_complete = true;
                    break;
                }
            }
        }
        break;

    default:
        break;
    }
}

void FileAssembler::processV1Message(const SMBv1Packet& pkt) {
    if (!pkt.isValid()) return;

    uint8_t cmd = pkt.command();
    const Smb1Header* hdr = pkt.header();
    uint16_t tid = le16toh(hdr->tid);
    const uint8_t* param_ptr = static_cast<const uint8_t*>(pkt.paramBlock());
    const uint8_t* data_ptr = pkt.dataBlock();
    size_t data_size = pkt.dataBlockSize();
    size_t param_size = (data_ptr >= param_ptr)
        ? static_cast<size_t>(data_ptr - param_ptr)
        : 0;

    switch (cmd) {
    case SMB_COM_TREE_CONNECT_ANDX:
        if (param_size >= sizeof(Smb1TreeConnectAndXResponse)) {
            auto* resp = reinterpret_cast<const Smb1TreeConnectAndXResponse*>(param_ptr);
            if (resp->word_count == 3 && data_size > 0) {
                size_t plen = 0;
                while (plen < data_size && data_ptr[plen] != '\0') plen++;
                std::string path(reinterpret_cast<const char*>(data_ptr), plen);
                if (!path.empty())
                    m_tree_map[tid] = path;
            }
        }
        break;

    case SMB_COM_NT_CREATE_ANDX:
        if (param_size >= sizeof(Smb1NtCreateAndXResponse)) {
            auto* resp = reinterpret_cast<const Smb1NtCreateAndXResponse*>(param_ptr);
            if (resp->word_count == 34 || resp->word_count == 42) {
                uint16_t fid = le16toh(resp->fid);
                std::string key = makeFileKey(tid, fid);
                ensureFileEntry(key);
                FileInfo& info = m_files[key];
                info.tree_id = tid;
                info.fid = fid;
                info.file_size = le64toh(resp->end_of_file);
                info.protocol = "SMBv1";

                std::map<uint32_t, std::string>::const_iterator sit = m_tree_map.find(tid);
                if (sit != m_tree_map.end())
                    info.share_path = sit->second;
            }
        }
        break;

    case SMB_COM_READ_ANDX:
        if (param_size >= sizeof(Smb1ReadAndXResponse)) {
            auto* resp = reinterpret_cast<const Smb1ReadAndXResponse*>(param_ptr);
            if (resp->word_count == 12) {
                uint16_t dlen = le16toh(resp->data_length);
                uint16_t doff = le16toh(resp->data_offset);
                if (dlen > 0 && static_cast<size_t>(doff) + dlen <= data_size) {
                    const uint8_t* data = data_ptr + doff;
                    std::string key;
                    for (std::map<std::string, FileInfo>::iterator it = m_files.begin();
                         it != m_files.end(); ++it) {
                        if (it->second.tree_id == tid && !it->second.is_complete) {
                            key = it->first;
                            break;
                        }
                    }
                    if (key.empty()) {
                        for (std::map<std::string, FileInfo>::iterator it = m_files.begin();
                             it != m_files.end(); ++it) {
                            if (!it->second.is_complete) {
                                key = it->first;
                                break;
                            }
                        }
                    }
                    if (key.empty()) {
                        key = makeFileKey(tid, 0xFFFF);
                        ensureFileEntry(key);
                        m_files[key].protocol = "SMBv1";
                        m_files[key].tree_id = tid;
                    }
                    appendData(key, data, dlen);
                }
            }
        }
        break;

    case SMB_COM_WRITE_ANDX:
        if (param_size >= sizeof(Smb1WriteAndXRequest)) {
            auto* req = reinterpret_cast<const Smb1WriteAndXRequest*>(param_ptr);
            if (req->word_count == 14) {
                uint16_t fid = le16toh(req->fid);
                uint16_t dlen = le16toh(req->data_length);
                uint16_t doff = le16toh(req->data_offset);
                std::string key = makeFileKey(tid, fid);
                ensureFileEntry(key);
                FileInfo& info = m_files[key];
                info.fid = fid;
                info.tree_id = tid;
                info.protocol = "SMBv1";

                if (dlen > 0 && static_cast<size_t>(doff) + dlen <= data_size) {
                    const uint8_t* data = data_ptr + doff;
                    appendData(key, data, dlen);
                }
            }
        }
        break;

    case SMB_COM_CLOSE:
        if (param_size >= sizeof(Smb1CloseRequest)) {
            auto* req = reinterpret_cast<const Smb1CloseRequest*>(param_ptr);
            if (req->word_count == 3) {
                uint16_t fid = le16toh(req->fid);
                std::string key = makeFileKey(tid, fid);
                ensureFileEntry(key);
                m_files[key].fid = fid;
                m_files[key].tree_id = tid;
                m_files[key].protocol = "SMBv1";
                m_files[key].is_complete = true;
            }
        }
        break;

    default:
        break;
    }
}

nlohmann::json FileAssembler::toJson() const {
    nlohmann::json j;
    nlohmann::json arr = nlohmann::json::array();

    for (std::map<std::string, FileInfo>::const_iterator it = m_files.begin();
         it != m_files.end(); ++it) {
        const FileInfo& info = it->second;
        nlohmann::json entry;

        if (info.filename.empty())
            entry["filename"] = nullptr;
        else
            entry["filename"] = info.filename;

        if (info.share_path.empty())
            entry["share_path"] = nullptr;
        else
            entry["share_path"] = info.share_path;

        entry["file_size"] = info.file_size;
        entry["bytes_read"] = info.bytes_read;
        entry["is_complete"] = info.is_complete;

        if (!info.is_complete && info.bytes_read < info.file_size)
            entry["note"] = "file incomplete";

        entry["tree_id"] = info.tree_id;

        if (!info.file_id_hex.empty())
            entry["file_id"] = info.file_id_hex;
        else
            entry["file_id"] = nullptr;

        entry["fid"] = info.fid;

        if (!info.protocol.empty())
            entry["protocol"] = info.protocol;
        else
            entry["protocol"] = nullptr;

        arr.push_back(entry);
    }
    j["files"] = arr;
    return j;
}

} // namespace smbparser
