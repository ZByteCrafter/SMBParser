#ifndef SMBPARSER_SMB_PARSER_H
#define SMBPARSER_SMB_PARSER_H

#include "types.h"
#include "smb1_packet.h"
#include "smb2_packet.h"
#include <nlohmann/json.hpp>
#include <vector>
#include <string>
#include <cstdint>

namespace smbparser {

enum class Transport { Unknown, NetBIOS, DirectTCP };

class SMBParser {
public:
    SMBParser();
    size_t feed(const uint8_t* data, size_t length);
    void flush();

    size_t messageCount() const { return m_v1_messages.size() + m_v2_messages.size(); }
    size_t errorCount() const { return m_errors; }
    Transport transport() const { return m_transport; }

    const SMBv1Packet* getV1Message(size_t index) const {
        return index < m_v1_messages.size() ? &m_v1_messages[index] : nullptr;
    }
    const SMBv2Packet* getV2Message(size_t index) const {
        return index < m_v2_messages.size() ? &m_v2_messages[index] : nullptr;
    }

    nlohmann::json toJson() const;
    std::string toJsonLines() const;

private:
    std::vector<uint8_t>              m_buffer;
    Transport                         m_transport = Transport::Unknown;
    std::vector<std::vector<uint8_t>> m_packet_storage;
    std::vector<SMBv1Packet>          m_v1_messages;
    std::vector<SMBv2Packet>          m_v2_messages;
    size_t                            m_errors = 0;

    bool detectTransport();
    void processBuffer();
    bool tryParse(const uint8_t* data, size_t len);
    void handleError();
    void consumeFromBuffer(size_t bytes);
};

} // namespace smbparser

#endif
