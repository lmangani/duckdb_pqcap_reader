#pragma once

#include <cstdint>
#include <string>

namespace pqcap_reader {

struct FooterLocator {
  uint64_t parquet_offset;
  uint64_t parquet_length;
};

// Parse fixed 44-byte footer block bytes.
// Returns true on success and populates out.
bool ParseFooterLocator(const std::string &bytes, FooterLocator &out);

} // namespace pqcap_reader
