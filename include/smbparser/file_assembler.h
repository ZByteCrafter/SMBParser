#ifndef SMBPARSER_FILE_ASSEMBLER_H
#define SMBPARSER_FILE_ASSEMBLER_H

#include "smb1_packet.h"
#include "smb2_packet.h"
#include "smb1_structs.h"
#include "smb2_structs.h"
#include "types.h"
#include <nlohmann/json.hpp>
#include <map>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace smbparser {

struct FileInfo {
    std::vector<uint8_t> data;
    std::string filename;
    std::string share_path;
    uint64_t  file_size = 0;
    uint64_t  bytes_read = 0;
    bool      is_complete = false;
    uint32_t  tree_id = 0;
    std::string file_id_hex;
    uint16_t  fid = 0;
    std::string protocol;
};

class FileAssembler {
public:
    void processV1Message(const SMBv1Packet& pkt);
    void processV2Message(const SMBv2Packet& pkt);
    const std::map<std::string, FileInfo>& files() const { return m_files; }
    nlohmann::json toJson() const;

private:
    std::map<uint32_t, std::string>     m_tree_map;
    std::map<uint16_t, std::string>     m_fid_filename;
    std::map<std::string, std::string>  m_fileid_filename;
    std::map<std::string, FileInfo>     m_files;
    std::string                         m_last_read_file_id;
    uint32_t                            m_last_read_tree_id = 0;

    std::string makeFileKey(uint32_t tree_id, uint16_t fid) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%u_%u", tree_id, fid);
        return buf;
    }
    std::string makeFileKeyV2(uint32_t tree_id, const std::string& file_id_hex) {
        return std::to_string(tree_id) + "_" + file_id_hex;
    }
    void appendData(const std::string& key, const uint8_t* data, size_t len);
    void ensureFileEntry(const std::string& key);
};

} // namespace smbparser

#endif
