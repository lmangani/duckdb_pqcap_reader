#include "pqcap_footer.h"

#include <cstring>

namespace pqcap_reader {

static constexpr uint32_t FOOTER_BLOCK_TYPE = 0x00000BEE;
static constexpr uint32_t FOOTER_BLOCK_SIZE = 44;
static constexpr uint32_t ENTERPRISE_ID = 0x51584950; // "QXIP"
static constexpr char FOOTER_MAGIC[8] = {'P', 'Q', 'C', 'A', 'P', 'F', 'T', 'R'};

static uint16_t ReadU16LE(const uint8_t *p) {
    return static_cast<uint16_t>(p[0]) |
           static_cast<uint16_t>(p[1] << 8);
}

static uint32_t ReadU32LE(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) |
           static_cast<uint32_t>(p[1] << 8) |
           static_cast<uint32_t>(p[2] << 16) |
           static_cast<uint32_t>(p[3] << 24);
}

static uint64_t ReadU64LE(const uint8_t *p) {
    return static_cast<uint64_t>(ReadU32LE(p)) |
           (static_cast<uint64_t>(ReadU32LE(p + 4)) << 32);
}

bool ParseFooterLocator(const std::string &bytes, FooterLocator &out) {
    if (bytes.size() != FOOTER_BLOCK_SIZE) {
        return false;
    }
    auto p = reinterpret_cast<const uint8_t *>(bytes.data());
    const uint32_t block_type = ReadU32LE(p + 0);
    const uint32_t block_len = ReadU32LE(p + 4);
    const uint32_t tail_len = ReadU32LE(p + FOOTER_BLOCK_SIZE - 4);
    if (block_type != FOOTER_BLOCK_TYPE || block_len != FOOTER_BLOCK_SIZE || tail_len != FOOTER_BLOCK_SIZE) {
        return false;
    }
    const uint32_t enterprise = ReadU32LE(p + 8);
    if (enterprise != ENTERPRISE_ID) {
        return false;
    }
    if (std::memcmp(p + 12, FOOTER_MAGIC, 8) != 0) {
        return false;
    }
    const uint16_t version = ReadU16LE(p + 20);
    if (version > 1) {
        return false;
    }
    const uint64_t parquet_offset = ReadU64LE(p + 24);
    const uint64_t parquet_length = ReadU64LE(p + 32);
    out.parquet_offset = parquet_offset;
    out.parquet_length = parquet_length;
    return true;
}

} // namespace pqcap_reader
