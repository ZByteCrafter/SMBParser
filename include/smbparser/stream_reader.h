#ifndef SMBPARSER_STREAM_READER_H
#define SMBPARSER_STREAM_READER_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <cstring>

namespace smbparser {

class StreamReader {
public:
    StreamReader(const uint8_t* data, size_t length)
        : m_data(data), m_length(length) {}

    template<typename T>
    bool read(size_t offset, T& out) const {
        if (offset + sizeof(T) > m_length) return false;
        const T* ptr = reinterpret_cast<const T*>(m_data + offset);
        out = *ptr;
        return true;
    }

    bool readBytes(size_t offset, size_t len, const uint8_t*& out) const {
        if (offset + len > m_length) return false;
        out = m_data + offset;
        return true;
    }

    bool readString(size_t offset, size_t max_chars,
                    std::string& out, bool is_unicode = false) const {
        out.clear();
        if (is_unicode) {
            size_t max_bytes = max_chars * 2;
            if (offset + 2 > m_length) return false;
            const uint8_t* p = m_data + offset;
            size_t chars_read = 0;
            size_t bytes_available = (m_length > offset) ? (m_length - offset) : 0;
            while (chars_read < max_chars && bytes_available >= 2) {
                uint16_t wch = static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
                if (wch == 0) break;
                out += static_cast<char>(wch & 0x7F);
                p += 2;
                chars_read++;
                bytes_available -= 2;
            }
        } else {
            if (offset >= m_length) return false;
            size_t available = m_length - offset;
            size_t limit = (max_chars < available) ? max_chars : available;
            const char* p = reinterpret_cast<const char*>(m_data + offset);
            for (size_t i = 0; i < limit && p[i] != '\0'; i++) {
                out += p[i];
            }
        }
        return true;
    }

    size_t length() const { return m_length; }

    bool canRead(size_t offset, size_t size) const {
        return offset + size <= m_length;
    }

private:
    const uint8_t* m_data;
    size_t m_length;
};

} // namespace smbparser

#endif // SMBPARSER_STREAM_READER_H
