#include "pqcap_packet_table.hpp"

#include "pqcap_duckdb_compat.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string.hpp"
#include "duckdb/common/types.hpp"
#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/function/table_function.hpp"

extern "C" {
#include "light_pcapng_ext.h"
}

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace duckdb {

namespace {

static constexpr uint32_t PCAPNG_MAGIC = 0x0A0D0D0A;
static constexpr uint32_t PCAP_MAGIC_LE = 0xA1B2C3D4;
static constexpr uint32_t PCAP_MAGIC_BE = 0xD4C3B2A1;
static constexpr uint32_t PCAP_NSEC_MAGIC_LE = 0xA1B23C4D;
static constexpr uint32_t PCAP_NSEC_MAGIC_BE = 0x4D3CB2A1;

static constexpr uint16_t DLT_EN10MB = 1;
static constexpr uint16_t DLT_RAW = 101;
static constexpr uint16_t DLT_LINUX_SLL = 113;

enum class CaptureReaderKind { PCAPNG, CLASSIC_PCAP };

struct ParsedL4Fields {
  string src_ip;
  string dst_ip;
  bool has_ports = false;
  int32_t src_port = 0;
  int32_t dst_port = 0;
  string l4_protocol = "UNKNOWN";
};

struct ClassicPcapReader {
  FILE *file = nullptr;
  bool swap_endian = false;
  bool nanosecond_ts = false;
  uint32_t linktype = DLT_EN10MB;
  bool finished = false;

  explicit ClassicPcapReader(const string &path) {
    file = std::fopen(path.c_str(), "rb");
    if (file == nullptr) {
      throw IOException("read_pqcap_packets: failed to open classic pcap '%s'",
                        path);
    }

    uint32_t magic = 0;
    if (std::fread(&magic, sizeof(magic), 1, file) != 1) {
      throw IOException("read_pqcap_packets: truncated pcap global header");
    }

    if (magic == PCAP_MAGIC_LE) {
      swap_endian = false;
      nanosecond_ts = false;
    } else if (magic == PCAP_MAGIC_BE) {
      swap_endian = true;
      nanosecond_ts = false;
    } else if (magic == PCAP_NSEC_MAGIC_LE) {
      swap_endian = false;
      nanosecond_ts = true;
    } else if (magic == PCAP_NSEC_MAGIC_BE) {
      swap_endian = true;
      nanosecond_ts = true;
    } else {
      throw InvalidInputException(
          "read_pqcap_packets: unsupported classic pcap magic in '%s'", path);
    }

    auto read_u16 = [&](uint16_t &out) {
      if (std::fread(&out, sizeof(out), 1, file) != 1) {
        throw IOException("read_pqcap_packets: truncated pcap global header");
      }
      if (swap_endian) {
        out = static_cast<uint16_t>((out >> 8) | ((out & 0xFF) << 8));
      }
    };
    auto read_u32 = [&](uint32_t &out) {
      if (std::fread(&out, sizeof(out), 1, file) != 1) {
        throw IOException("read_pqcap_packets: truncated pcap global header");
      }
      if (swap_endian) {
        out = ((out >> 24) & 0xFF) | ((out >> 8) & 0xFF00) |
              ((out << 8) & 0xFF0000) | ((out << 24) & 0xFF000000);
      }
    };

    uint16_t version_major = 0;
    uint16_t version_minor = 0;
    int32_t thiszone = 0;
    uint32_t sigfigs = 0;
    uint32_t snaplen = 0;
    read_u16(version_major);
    read_u16(version_minor);
    if (std::fread(&thiszone, sizeof(thiszone), 1, file) != 1) {
      throw IOException("read_pqcap_packets: truncated pcap global header");
    }
    if (swap_endian) {
      thiszone = static_cast<int32_t>(
          ((static_cast<uint32_t>(thiszone) >> 24) & 0xFF) |
          ((static_cast<uint32_t>(thiszone) >> 8) & 0xFF00) |
          ((static_cast<uint32_t>(thiszone) << 8) & 0xFF0000) |
          ((static_cast<uint32_t>(thiszone) << 24) & 0xFF000000));
    }
    read_u32(sigfigs);
    read_u32(snaplen);
    read_u32(linktype);
    (void)version_major;
    (void)version_minor;
    (void)thiszone;
    (void)sigfigs;
    (void)snaplen;
  }

  ~ClassicPcapReader() {
    if (file != nullptr) {
      std::fclose(file);
      file = nullptr;
    }
  }

  ClassicPcapReader(const ClassicPcapReader &) = delete;
  ClassicPcapReader &operator=(const ClassicPcapReader &) = delete;

  bool Next(light_packet_header &header, vector<uint8_t> &packet_data) {
    if (finished || file == nullptr) {
      return false;
    }

    uint32_t ts_sec = 0;
    uint32_t ts_sub = 0;
    uint32_t incl_len = 0;
    uint32_t orig_len = 0;
    if (std::fread(&ts_sec, sizeof(ts_sec), 1, file) != 1) {
      finished = true;
      return false;
    }
    if (std::fread(&ts_sub, sizeof(ts_sub), 1, file) != 1) {
      finished = true;
      return false;
    }
    if (std::fread(&incl_len, sizeof(incl_len), 1, file) != 1) {
      finished = true;
      return false;
    }
    if (std::fread(&orig_len, sizeof(orig_len), 1, file) != 1) {
      finished = true;
      return false;
    }

    if (swap_endian) {
      auto swap32 = [](uint32_t v) {
        return ((v >> 24) & 0xFF) | ((v >> 8) & 0xFF00) |
               ((v << 8) & 0xFF0000) | ((v << 24) & 0xFF000000);
      };
      ts_sec = swap32(ts_sec);
      ts_sub = swap32(ts_sub);
      incl_len = swap32(incl_len);
      orig_len = swap32(orig_len);
    }

    packet_data.resize(incl_len);
    if (incl_len > 0 &&
        std::fread(packet_data.data(), 1, incl_len, file) != incl_len) {
      throw IOException("read_pqcap_packets: truncated pcap packet data");
    }

    header = {};
    header.interface_id = 0;
    header.captured_length = incl_len;
    header.original_length = orig_len;
    header.data_link = static_cast<uint16_t>(linktype);
    header.timestamp.tv_sec = static_cast<time_t>(ts_sec);
    if (nanosecond_ts) {
      header.timestamp.tv_nsec = static_cast<long>(ts_sub);
    } else {
      header.timestamp.tv_nsec = static_cast<long>(ts_sub) * 1000L;
    }
    header.comment = nullptr;
    header.comment_length = 0;
    return true;
  }
};

static CaptureReaderKind DetectCaptureFormat(const string &path) {
  FILE *file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    throw IOException("read_pqcap_packets: failed to open '%s'", path);
  }
  uint32_t magic = 0;
  if (std::fread(&magic, sizeof(magic), 1, file) != 1) {
    std::fclose(file);
    throw IOException("read_pqcap_packets: file too small: '%s'", path);
  }
  std::fclose(file);

  if (magic == PCAPNG_MAGIC) {
    return CaptureReaderKind::PCAPNG;
  }
  if (magic == PCAP_MAGIC_LE || magic == PCAP_MAGIC_BE ||
      magic == PCAP_NSEC_MAGIC_LE || magic == PCAP_NSEC_MAGIC_BE) {
    return CaptureReaderKind::CLASSIC_PCAP;
  }
  throw InvalidInputException("read_pqcap_packets: unsupported capture format "
                              "(expected pcap or pcapng): '%s'",
                              path);
}

static uint16_t ReadBE16(const uint8_t *ptr) {
  return static_cast<uint16_t>((static_cast<uint16_t>(ptr[0]) << 8) |
                               static_cast<uint16_t>(ptr[1]));
}

static string FormatIPv4(const uint8_t *src) {
  return StringUtil::Format("%u.%u.%u.%u", src[0], src[1], src[2], src[3]);
}

static string FormatIPv6(const uint8_t *src) {
  std::array<uint16_t, 8> groups{};
  for (idx_t i = 0; i < groups.size(); i++) {
    groups[i] = ReadBE16(src + (i * 2));
  }
  return StringUtil::Format("%x:%x:%x:%x:%x:%x:%x:%x", groups[0], groups[1],
                            groups[2], groups[3], groups[4], groups[5],
                            groups[6], groups[7]);
}

static ParsedL4Fields ParseIPv4(const uint8_t *cursor, size_t remaining) {
  ParsedL4Fields out;
  if (remaining < 20) {
    return out;
  }
  auto ihl = static_cast<size_t>((cursor[0] & 0x0F) * 4);
  if (ihl < 20 || remaining < ihl) {
    return out;
  }
  auto protocol = cursor[9];
  out.src_ip = FormatIPv4(cursor + 12);
  out.dst_ip = FormatIPv4(cursor + 16);
  cursor += ihl;
  remaining -= ihl;

  if (protocol == 6 && remaining >= 20) {
    auto tcp_header_len = static_cast<size_t>(((cursor[12] >> 4) & 0x0F) * 4);
    if (tcp_header_len >= 20 && remaining >= tcp_header_len) {
      out.has_ports = true;
      out.src_port = ReadBE16(cursor);
      out.dst_port = ReadBE16(cursor + 2);
      out.l4_protocol = "TCP";
    }
  } else if (protocol == 17 && remaining >= 8) {
    out.has_ports = true;
    out.src_port = ReadBE16(cursor);
    out.dst_port = ReadBE16(cursor + 2);
    out.l4_protocol = "UDP";
  } else {
    out.l4_protocol = StringUtil::Format("IP_%u", protocol);
  }
  return out;
}

static ParsedL4Fields ParseIPv6(const uint8_t *cursor, size_t remaining) {
  ParsedL4Fields out;
  if (remaining < 40) {
    return out;
  }
  auto next_header = cursor[6];
  out.src_ip = FormatIPv6(cursor + 8);
  out.dst_ip = FormatIPv6(cursor + 24);
  cursor += 40;
  remaining -= 40;

  if (next_header == 6 && remaining >= 20) {
    auto tcp_header_len = static_cast<size_t>(((cursor[12] >> 4) & 0x0F) * 4);
    if (tcp_header_len >= 20 && remaining >= tcp_header_len) {
      out.has_ports = true;
      out.src_port = ReadBE16(cursor);
      out.dst_port = ReadBE16(cursor + 2);
      out.l4_protocol = "TCP";
    }
  } else if (next_header == 17 && remaining >= 8) {
    out.has_ports = true;
    out.src_port = ReadBE16(cursor);
    out.dst_port = ReadBE16(cursor + 2);
    out.l4_protocol = "UDP";
  } else {
    out.l4_protocol = StringUtil::Format("IP6_%u", next_header);
  }
  return out;
}

static ParsedL4Fields ParseL4Fields(uint16_t data_link,
                                    const uint8_t *packet_data,
                                    uint32_t captured_length) {
  ParsedL4Fields out;
  if (packet_data == nullptr || captured_length == 0) {
    return out;
  }

  const uint8_t *cursor = packet_data;
  size_t remaining = captured_length;

  if (data_link == DLT_RAW) {
    if ((cursor[0] >> 4) == 4) {
      return ParseIPv4(cursor, remaining);
    }
    if ((cursor[0] >> 4) == 6) {
      return ParseIPv6(cursor, remaining);
    }
    out.l4_protocol = "RAW";
    return out;
  }

  if (data_link == DLT_LINUX_SLL) {
    if (remaining < 16) {
      out.l4_protocol = "SLL";
      return out;
    }
    auto protocol = ReadBE16(cursor + 14);
    cursor += 16;
    remaining -= 16;
    if (protocol == 0x0800) {
      return ParseIPv4(cursor, remaining);
    }
    if (protocol == 0x86DD) {
      return ParseIPv6(cursor, remaining);
    }
    out.l4_protocol = StringUtil::Format("SLL_0x%04X", protocol);
    return out;
  }

  // Default: treat as Ethernet (DLT_EN10MB and friends).
  if (remaining < 14) {
    out.l4_protocol = StringUtil::Format("LINK_%u", data_link);
    return out;
  }

  uint16_t ether_type = ReadBE16(cursor + 12);
  cursor += 14;
  remaining -= 14;

  if ((ether_type == 0x8100 || ether_type == 0x88A8) && remaining >= 4) {
    ether_type = ReadBE16(cursor + 2);
    cursor += 4;
    remaining -= 4;
  }

  if (ether_type == 0x0800) {
    return ParseIPv4(cursor, remaining);
  }
  if (ether_type == 0x86DD) {
    return ParseIPv6(cursor, remaining);
  }

  out.l4_protocol = StringUtil::Format("ETH_0x%04X", ether_type);
  return out;
}

static int64_t TimestampMicros(const light_packet_header &header) {
  return static_cast<int64_t>(header.timestamp.tv_sec) * 1000000LL +
         static_cast<int64_t>(header.timestamp.tv_nsec / 1000);
}

static void SetRowValue(DataChunk &output, idx_t col, idx_t row,
                        const Value &val) {
  pqcap_compat::SetChunkValue(output, col, row, val);
}

static void SetPayloadValue(DataChunk &output, idx_t row, const uint8_t *data,
                            idx_t len) {
  auto &payload_vec = output.data[11];
  pqcap_compat::FlattenVector(payload_vec, row + 1);
  if (data == nullptr || len == 0) {
    FlatVector::SetNull(payload_vec, row, true);
    return;
  }
  auto blob = StringVector::AddStringOrBlob(payload_vec,
                                            const_char_ptr_cast(data), len);
  pqcap_compat::FlatVectorGetData<string_t>(payload_vec)[row] = blob;
  FlatVector::SetNull(payload_vec, row, false);
}

} // namespace

struct PqcapPacketsBindData : public TableFunctionData {
  explicit PqcapPacketsBindData(string source_path_p)
      : source_path(std::move(source_path_p)) {}

  string source_path;
};

struct PqcapPacketsGlobalState : public GlobalTableFunctionState {
  explicit PqcapPacketsGlobalState(CaptureReaderKind kind_p) : kind(kind_p) {}
  ~PqcapPacketsGlobalState() override {
    if (pcapng_reader != nullptr) {
      light_pcapng_close(pcapng_reader);
      pcapng_reader = nullptr;
    }
  }

  idx_t MaxThreads() const override { return 1; }

  CaptureReaderKind kind;
  light_pcapng_t *pcapng_reader = nullptr;
  unique_ptr<ClassicPcapReader> classic_reader;
  bool finished = false;
};

static unique_ptr<FunctionData>
ReadPqcapPacketsBind(ClientContext &context, TableFunctionBindInput &input,
                     vector<LogicalType> &return_types, vector<string> &names) {
  if (input.inputs.size() != 1) {
    throw BinderException(
        "read_pqcap_packets(path): expected exactly one argument");
  }
  if (input.inputs[0].IsNull()) {
    throw BinderException("read_pqcap_packets(path): path argument is NULL");
  }
  auto path = input.inputs[0].GetValue<string>();

  return_types = {
      LogicalType::BIGINT,  LogicalType::UBIGINT, LogicalType::USMALLINT,
      LogicalType::UBIGINT, LogicalType::UBIGINT, LogicalType::VARCHAR,
      LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::INTEGER,
      LogicalType::INTEGER, LogicalType::VARCHAR, LogicalType::BLOB};
  names = {"timestamp_micros", "interface_id", "data_link",   "captured_length",
           "orig_len",         "comment",      "src_ip",      "dst_ip",
           "src_port",         "dst_port",     "l4_protocol", "payload"};
  return make_uniq<PqcapPacketsBindData>(path);
}

static unique_ptr<GlobalTableFunctionState>
ReadPqcapPacketsInitGlobal(ClientContext &context,
                           TableFunctionInitInput &input) {
  auto &bind_data = input.bind_data->Cast<PqcapPacketsBindData>();
  auto kind = DetectCaptureFormat(bind_data.source_path);
  auto state = make_uniq<PqcapPacketsGlobalState>(kind);

  if (kind == CaptureReaderKind::PCAPNG) {
    state->pcapng_reader =
        light_pcapng_open_read(bind_data.source_path.c_str(), LIGHT_FALSE);
    if (state->pcapng_reader == nullptr) {
      throw IOException("read_pqcap_packets: failed to open pcapng file '%s'",
                        bind_data.source_path);
    }
  } else {
    state->classic_reader = make_uniq<ClassicPcapReader>(bind_data.source_path);
  }
  return std::move(state);
}

static void ReadPqcapPacketsFunction(ClientContext &context,
                                     TableFunctionInput &data_p,
                                     DataChunk &output) {
  auto &state = data_p.global_state->Cast<PqcapPacketsGlobalState>();
  if (state.finished) {
    output.SetCardinality(0);
    return;
  }

  idx_t row_count = 0;
  for (; row_count < STANDARD_VECTOR_SIZE; row_count++) {
    light_packet_header header{};
    const uint8_t *packet_ptr = nullptr;
    vector<uint8_t> packet_bytes;
    bool has_packet = false;

    if (state.kind == CaptureReaderKind::PCAPNG) {
      if (!light_get_next_packet(state.pcapng_reader, &header, &packet_ptr)) {
        state.finished = true;
        break;
      }
      has_packet = true;
    } else {
      if (!state.classic_reader->Next(header, packet_bytes)) {
        state.finished = true;
        break;
      }
      packet_ptr = packet_bytes.data();
      has_packet = true;
    }

    if (!has_packet) {
      state.finished = true;
      break;
    }

    if (header.captured_length > 0 && packet_ptr != nullptr) {
      packet_bytes.assign(packet_ptr, packet_ptr + header.captured_length);
      packet_ptr = packet_bytes.data();
    } else {
      packet_bytes.clear();
      packet_ptr = nullptr;
    }

    auto parsed = ParseL4Fields(header.data_link, packet_ptr,
                                static_cast<uint32_t>(packet_bytes.size()));
    string comment;
    if (header.comment != nullptr && header.comment_length > 0) {
      comment.assign(header.comment, header.comment_length);
    }

    SetRowValue(output, 0, row_count, Value::BIGINT(TimestampMicros(header)));
    SetRowValue(output, 1, row_count, Value::UBIGINT(header.interface_id));
    SetRowValue(output, 2, row_count,
                Value::USMALLINT(static_cast<uint16_t>(header.data_link)));
    SetRowValue(output, 3, row_count, Value::UBIGINT(header.captured_length));
    SetRowValue(output, 4, row_count, Value::UBIGINT(header.original_length));
    SetRowValue(output, 5, row_count,
                comment.empty() ? Value(LogicalType::VARCHAR) : Value(comment));
    SetRowValue(output, 6, row_count,
                parsed.src_ip.empty() ? Value() : Value(parsed.src_ip));
    SetRowValue(output, 7, row_count,
                parsed.dst_ip.empty() ? Value() : Value(parsed.dst_ip));
    SetRowValue(output, 8, row_count,
                parsed.has_ports ? Value::INTEGER(parsed.src_port)
                                 : Value(LogicalType::INTEGER));
    SetRowValue(output, 9, row_count,
                parsed.has_ports ? Value::INTEGER(parsed.dst_port)
                                 : Value(LogicalType::INTEGER));
    SetRowValue(output, 10, row_count, Value(parsed.l4_protocol));
    SetPayloadValue(output, row_count, packet_ptr, packet_bytes.size());
  }
  output.SetCardinality(row_count);
}

void RegisterPqcapPacketTableFunction(ExtensionLoader &loader) {
  TableFunction packet_table("read_pqcap_packets", {LogicalType::VARCHAR},
                             ReadPqcapPacketsFunction, ReadPqcapPacketsBind,
                             ReadPqcapPacketsInitGlobal);
  packet_table.projection_pushdown = false;
  loader.RegisterFunction(packet_table);
}

} // namespace duckdb
