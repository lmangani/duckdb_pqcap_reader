#include "pqcap_packet_table.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string.hpp"
#include "duckdb/common/types.hpp"
#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/common/vector.hpp"
#include "duckdb/function/table_function.hpp"

extern "C" {
#include "light_pcapng_ext.h"
}

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace duckdb {

struct ParsedPacket {
  int64_t timestamp_micros;
  string src_ip;
  string dst_ip;
  bool has_ports;
  int32_t src_port;
  int32_t dst_port;
  string l4_protocol;
  uint64_t orig_len;
  vector<uint8_t> payload;
};

struct PqcapPacketsBindData : public TableFunctionData {
  explicit PqcapPacketsBindData(string source_path_p)
      : source_path(std::move(source_path_p)) {}

  string source_path;
};

struct PqcapPacketsGlobalState : public GlobalTableFunctionState {
  explicit PqcapPacketsGlobalState(light_pcapng_t *reader_p)
      : reader(reader_p) {}
  ~PqcapPacketsGlobalState() override {
    if (reader != nullptr) {
      light_pcapng_close(reader);
      reader = nullptr;
    }
  }

  idx_t MaxThreads() const override { return 1; }

  light_pcapng_t *reader;
  bool finished = false;
};

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

static ParsedPacket ParsePacket(const light_packet_header &header,
                                const uint8_t *packet_data) {
  ParsedPacket out;
  out.timestamp_micros =
      static_cast<int64_t>(header.timestamp.tv_sec) * 1000000LL +
      static_cast<int64_t>(header.timestamp.tv_nsec / 1000);
  out.has_ports = false;
  out.src_port = 0;
  out.dst_port = 0;
  out.l4_protocol = "UNKNOWN";
  out.orig_len = header.original_length;

  if (packet_data == nullptr || header.captured_length < 14) {
    return out;
  }

  const uint8_t *cursor = packet_data;
  size_t remaining = header.captured_length;
  uint16_t ether_type = ReadBE16(cursor + 12);
  cursor += 14;
  remaining -= 14;

  // Skip one VLAN/QinQ tag if present.
  if ((ether_type == 0x8100 || ether_type == 0x88A8) && remaining >= 4) {
    ether_type = ReadBE16(cursor + 2);
    cursor += 4;
    remaining -= 4;
  }

  if (ether_type == 0x0800 && remaining >= 20) {
    // IPv4
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
      // TCP
      auto tcp_header_len = static_cast<size_t>(((cursor[12] >> 4) & 0x0F) * 4);
      if (tcp_header_len < 20 || remaining < tcp_header_len) {
        return out;
      }
      out.has_ports = true;
      out.src_port = ReadBE16(cursor);
      out.dst_port = ReadBE16(cursor + 2);
      out.l4_protocol = "TCP";
      cursor += tcp_header_len;
      remaining -= tcp_header_len;
      out.payload.assign(cursor, cursor + remaining);
    } else if (protocol == 17 && remaining >= 8) {
      // UDP
      out.has_ports = true;
      out.src_port = ReadBE16(cursor);
      out.dst_port = ReadBE16(cursor + 2);
      out.l4_protocol = "UDP";
      cursor += 8;
      remaining -= 8;
      out.payload.assign(cursor, cursor + remaining);
    } else {
      out.l4_protocol = StringUtil::Format("IP_%u", protocol);
      out.payload.assign(cursor, cursor + remaining);
    }
    return out;
  }

  if (ether_type == 0x86DD && remaining >= 40) {
    // IPv6
    auto next_header = cursor[6];
    out.src_ip = FormatIPv6(cursor + 8);
    out.dst_ip = FormatIPv6(cursor + 24);
    cursor += 40;
    remaining -= 40;

    if (next_header == 6 && remaining >= 20) {
      auto tcp_header_len = static_cast<size_t>(((cursor[12] >> 4) & 0x0F) * 4);
      if (tcp_header_len < 20 || remaining < tcp_header_len) {
        return out;
      }
      out.has_ports = true;
      out.src_port = ReadBE16(cursor);
      out.dst_port = ReadBE16(cursor + 2);
      out.l4_protocol = "TCP";
      cursor += tcp_header_len;
      remaining -= tcp_header_len;
      out.payload.assign(cursor, cursor + remaining);
    } else if (next_header == 17 && remaining >= 8) {
      out.has_ports = true;
      out.src_port = ReadBE16(cursor);
      out.dst_port = ReadBE16(cursor + 2);
      out.l4_protocol = "UDP";
      cursor += 8;
      remaining -= 8;
      out.payload.assign(cursor, cursor + remaining);
    } else {
      out.l4_protocol = StringUtil::Format("IP6_%u", next_header);
      out.payload.assign(cursor, cursor + remaining);
    }
    return out;
  }

  // Non-IP ethernet payload
  out.l4_protocol = StringUtil::Format("ETH_0x%04X", ether_type);
  out.payload.assign(cursor, cursor + remaining);
  return out;
}

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

  return_types = {LogicalType::BIGINT,  LogicalType::VARCHAR,
                  LogicalType::VARCHAR, LogicalType::INTEGER,
                  LogicalType::INTEGER, LogicalType::VARCHAR,
                  LogicalType::UBIGINT, LogicalType::BLOB};
  names = {"timestamp_micros", "src_ip",      "dst_ip",   "src_port",
           "dst_port",         "l4_protocol", "orig_len", "payload"};
  return make_uniq<PqcapPacketsBindData>(path);
}

static unique_ptr<GlobalTableFunctionState>
ReadPqcapPacketsInitGlobal(ClientContext &context,
                           TableFunctionInitInput &input) {
  auto &bind_data = input.bind_data->Cast<PqcapPacketsBindData>();
  auto *reader =
      light_pcapng_open_read(bind_data.source_path.c_str(), LIGHT_FALSE);
  if (reader == nullptr) {
    throw IOException("read_pqcap_packets: failed to open pcapng file '%s'",
                      bind_data.source_path);
  }
  return make_uniq<PqcapPacketsGlobalState>(reader);
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
    const uint8_t *packet_data = nullptr;
    if (!light_get_next_packet(state.reader, &header, &packet_data)) {
      state.finished = true;
      break;
    }

    auto parsed = ParsePacket(header, packet_data);
    output.SetValue(0, row_count, Value::BIGINT(parsed.timestamp_micros));
    output.SetValue(1, row_count,
                    parsed.src_ip.empty() ? Value() : Value(parsed.src_ip));
    output.SetValue(2, row_count,
                    parsed.dst_ip.empty() ? Value() : Value(parsed.dst_ip));
    output.SetValue(3, row_count,
                    parsed.has_ports ? Value::INTEGER(parsed.src_port)
                                     : Value(LogicalType::INTEGER));
    output.SetValue(4, row_count,
                    parsed.has_ports ? Value::INTEGER(parsed.dst_port)
                                     : Value(LogicalType::INTEGER));
    output.SetValue(5, row_count, Value(parsed.l4_protocol));
    output.SetValue(6, row_count, Value::UBIGINT(parsed.orig_len));
    output.SetValue(
        7, row_count,
        parsed.payload.empty()
            ? Value::BLOB_RAW("")
            : Value::BLOB(const_data_ptr_cast(parsed.payload.data()),
                          parsed.payload.size()));
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
