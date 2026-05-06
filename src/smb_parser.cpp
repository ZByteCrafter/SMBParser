#include <smbparser/smb_parser.h>
#include <cstring>

namespace smbparser {

SMBParser::SMBParser() {}

size_t SMBParser::feed(const uint8_t* data, size_t length) {
    size_t prev_count = messageCount();
    m_buffer.insert(m_buffer.end(), data, data + length);
    if (m_transport == Transport::Unknown) {
        detectTransport();
    }
    if (m_transport != Transport::Unknown) {
        processBuffer();
    }
    return messageCount() - prev_count;
}

void SMBParser::flush() {
    if (m_transport != Transport::Unknown && !m_buffer.empty()) {
        processBuffer();
    }
}

bool SMBParser::detectTransport() {
    for (size_t i = 0; i + 4 <= m_buffer.size(); i++) {
        if ((m_buffer[i] == 0xFF || m_buffer[i] == 0xFE) &&
            m_buffer[i + 1] == 'S' && m_buffer[i + 2] == 'M' && m_buffer[i + 3] == 'B') {
            if (i > 0) {
                m_errors++;
                consumeFromBuffer(i);
            }
            m_transport = Transport::DirectTCP;
            return true;
        }

        if (m_buffer[i] == 0x00 && i + 8 <= m_buffer.size()) {
            uint32_t nb_len = (static_cast<uint32_t>(m_buffer[i + 1]) << 16)
                            | (static_cast<uint32_t>(m_buffer[i + 2]) << 8)
                            | m_buffer[i + 3];
            if (nb_len > 0 && nb_len <= 0x1FFFFF) {
                // Validate full 4-byte SMB magic, not just the first byte
                const uint8_t* p = m_buffer.data() + i + 4;
                if ((p[0] == 0xFF && p[1] == 'S' && p[2] == 'M' && p[3] == 'B') ||
                    (p[0] == 0xFE && p[1] == 'S' && p[2] == 'M' && p[3] == 'B')) {
                    if (i > 0) {
                        m_errors++;
                        consumeFromBuffer(i);
                    }
                    m_transport = Transport::NetBIOS;
                    return true;
                }
            }
        }
    }

    return false;
}

void SMBParser::processBuffer() {
    while (true) {
        if (m_transport == Transport::NetBIOS) {
            if (m_buffer.size() < 4) return;
            uint32_t nb_len = (static_cast<uint32_t>(m_buffer[1]) << 16)
                            | (static_cast<uint32_t>(m_buffer[2]) << 8)
                            | m_buffer[3];
            size_t total = 4 + nb_len;
            if (m_buffer.size() < total) return;
            size_t consumed = tryParse(m_buffer.data() + 4, nb_len);
            if (consumed > 0) {
                consumeFromBuffer(total);
            } else {
                handleError();
            }
        } else {
            if (m_buffer.size() < 4) return;
            uint8_t magic = m_buffer[0];
            if (magic != 0xFF && magic != 0xFE) {
                handleError();
                continue;
            }
            size_t consumed = tryParse(m_buffer.data(), m_buffer.size());
            if (consumed > 0) {
                // Consume exactly the parsed message bytes. If the returned size
                // exceeds the buffer, fall back to scanning for the next SMB magic.
                if (consumed <= m_buffer.size()) {
                    consumeFromBuffer(consumed);
                } else {
                    // Scan for next magic as safety fallback
                    const uint8_t mV1[4] = {0xFF, 'S', 'M', 'B'};
                    const uint8_t mV2[4] = {0xFE, 'S', 'M', 'B'};
                    size_t end = consumed;
                    for (size_t i = 4; i + 4 <= m_buffer.size(); i++) {
                        if (memcmp(m_buffer.data() + i, mV1, 4) == 0 ||
                            memcmp(m_buffer.data() + i, mV2, 4) == 0) {
                            end = i;
                            break;
                        }
                    }
                    consumeFromBuffer(end);
                }
            } else {
                handleError();
            }
        }
    }
}

size_t SMBParser::tryParse(const uint8_t* data, size_t len) {
    if (len < 4) return 0;

    if (data[0] == 0xFF && data[1] == 'S' && data[2] == 'M' && data[3] == 'B') {
        SMBv1Packet pkt(data, len);
        if (pkt.isValid()) {
            // Compute exact message size before storing
            size_t exact_size = sizeof(Smb1Header);
            size_t wc_offset = sizeof(Smb1Header);
            if (wc_offset < len) {
                uint8_t word_count = data[wc_offset];
                size_t param_end = wc_offset + 1 + static_cast<size_t>(word_count) * 2;
                if (param_end + 2 <= len) {
                    uint16_t byte_count;
                    std::memcpy(&byte_count, data + param_end, sizeof(uint16_t));
                    byte_count = smb_le16toh(byte_count);
                    exact_size = param_end + 2 + byte_count;
                }
            }
            // Store only the exact message bytes
            m_packet_storage.emplace_back(data, data + exact_size);
            const auto& stored = m_packet_storage.back();
            m_v1_messages.emplace_back(stored.data(), stored.size());
            return exact_size;
        }
        return 0;
    }

    if (data[0] == 0xFE && data[1] == 'S' && data[2] == 'M' && data[3] == 'B') {
        // Use a loop for compounding instead of recursion
        size_t total_consumed = 0;
        size_t offset = 0;
        while (offset < len) {
            if (offset + 4 > len) break;
            if (data[offset] != 0xFE || data[offset+1] != 'S' ||
                data[offset+2] != 'M' || data[offset+3] != 'B') break;

            SMBv2Packet pkt(data + offset, len - offset);
            if (!pkt.isValid()) {
                return (offset > 0) ? offset : 0; // return consumed so far, or 0 for first failure
            }

            if (pkt.hasNextCommand()) {
                size_t next = pkt.nextCommandOffset();
                if (next > offset && next < len) {
                    // Store only up to the next compound's start
                    m_packet_storage.emplace_back(data + offset, data + next);
                    const auto& stored = m_packet_storage.back();
                    m_v2_messages.emplace_back(stored.data(), stored.size());
                    offset = next; // follow the compound chain
                } else {
                    // Invalid next_command — store all remaining as one packet
                    m_packet_storage.emplace_back(data + offset, data + len);
                    const auto& stored = m_packet_storage.back();
                    m_v2_messages.emplace_back(stored.data(), stored.size());
                    total_consumed = len;
                    break;
                }
            } else {
                // Last compound: determine actual message boundary by scanning
                const uint8_t mV1[4] = {0xFF, 'S', 'M', 'B'};
                const uint8_t mV2[4] = {0xFE, 'S', 'M', 'B'};
                size_t msg_end = offset + sizeof(Smb2Header);
                size_t actual_end = len;
                for (size_t i = msg_end; i + 4 <= len; i++) {
                    if (memcmp(data + i, mV1, 4) == 0 ||
                        memcmp(data + i, mV2, 4) == 0) {
                        actual_end = i;
                        break;
                    }
                }
                // Store only up to the actual message boundary
                m_packet_storage.emplace_back(data + offset, data + actual_end);
                const auto& stored = m_packet_storage.back();
                m_v2_messages.emplace_back(stored.data(), stored.size());
                total_consumed = actual_end;
                break;
            }
        }
        return (total_consumed > 0) ? total_consumed : len;
    }

    return 0;
}

void SMBParser::handleError() {
    m_errors++;
    const uint8_t magic_v1[4] = {0xFF, 'S', 'M', 'B'};
    const uint8_t magic_v2[4] = {0xFE, 'S', 'M', 'B'};
    for (size_t i = 1; i + 4 <= m_buffer.size(); i++) {
        if (memcmp(m_buffer.data() + i, magic_v1, 4) == 0 ||
            memcmp(m_buffer.data() + i, magic_v2, 4) == 0) {
            consumeFromBuffer(i);
            return;
        }
    }
    m_buffer.clear();
}

void SMBParser::consumeFromBuffer(size_t bytes) {
    if (bytes >= m_buffer.size()) {
        m_buffer.clear();
    } else {
        m_buffer.erase(m_buffer.begin(), m_buffer.begin() + static_cast<std::ptrdiff_t>(bytes));
    }
}

nlohmann::json SMBParser::toJson() const {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& m : m_v1_messages) arr.push_back(m.toJson());
    for (const auto& m : m_v2_messages) arr.push_back(m.toJson());
    return arr;
}

std::string SMBParser::toJsonLines() const {
    std::string result;
    for (const auto& m : m_v1_messages) { result += m.toJson().dump() + "\n"; }
    for (const auto& m : m_v2_messages) { result += m.toJson().dump() + "\n"; }
    return result;
}

} // namespace smbparser
