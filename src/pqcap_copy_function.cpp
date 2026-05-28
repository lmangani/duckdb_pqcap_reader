#include "pqcap_copy_function.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception/binder_exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/copy_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/connection.hpp"
#include "duckdb/main/database.hpp"

extern "C" {
#include "light_pcapng_ext.h"
}

#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace duckdb {
namespace {

static const uint32_t PQCAP_CUSTOM_BLOCK_TYPE = 0x00000BAD;
static const uint32_t PQCAP_FOOTER_BLOCK_TYPE = 0x00000BEE;
static const uint32_t PQCAP_ENTERPRISE_ID = 0x51584950;
static const char PQCAP_MAGIC[] = "PQCAPMETA";
static const char PQCAP_FOOTER_MAGIC[] = "PQCAPFTR";

struct PacketRowData {
  uint64_t ts_micros = 0;
  uint64_t orig_len = 0;
  std::string packet_bytes;
  std::string src_ip;
  std::string dst_ip;
  bool has_src_port = false;
  bool has_dst_port = false;
  uint32_t src_port = 0;
  uint32_t dst_port = 0;
  std::string protocols;
};

struct PqcapCopyBindData : public FunctionData {
  std::string mode = "pqcap";
  uint16_t linktype = 1;

  idx_t idx_timestamp_micros = DConstants::INVALID_INDEX;
  idx_t idx_orig_len = DConstants::INVALID_INDEX;
  idx_t idx_payload = DConstants::INVALID_INDEX;
  idx_t idx_src_ip = DConstants::INVALID_INDEX;
  idx_t idx_dst_ip = DConstants::INVALID_INDEX;
  idx_t idx_src_port = DConstants::INVALID_INDEX;
  idx_t idx_dst_port = DConstants::INVALID_INDEX;
  idx_t idx_protocols = DConstants::INVALID_INDEX;

  unique_ptr<FunctionData> Copy() const override {
    return make_uniq<PqcapCopyBindData>(*this);
  }
  bool Equals(const FunctionData &other_p) const override {
    const auto &other = other_p.Cast<const PqcapCopyBindData>();
    return mode == other.mode && linktype == other.linktype &&
           idx_timestamp_micros == other.idx_timestamp_micros &&
           idx_orig_len == other.idx_orig_len &&
           idx_payload == other.idx_payload && idx_src_ip == other.idx_src_ip &&
           idx_dst_ip == other.idx_dst_ip &&
           idx_src_port == other.idx_src_port &&
           idx_dst_port == other.idx_dst_port &&
           idx_protocols == other.idx_protocols;
  }
};

struct PqcapCopyGlobalState : public GlobalFunctionData {
  light_pcapng_t *writer = nullptr;
  std::vector<PacketRowData> rows;
  std::mutex lock;
  std::string output_path;
};

struct PacketLocation {
  uint64_t offset;
  uint64_t size;

  PacketLocation(uint64_t offset_p, uint64_t size_p) : offset(offset_p), size(size_p) {
  }
};

static idx_t FindColumnIdx(const vector<string> &names, const string &needle) {
  for (idx_t i = 0; i < names.size(); i++) {
    if (StringUtil::CIEquals(names[i], needle)) {
      return i;
    }
  }
  return DConstants::INVALID_INDEX;
}

static uint64_t ParseUInt64(const Value &value, const string &name) {
  Value casted = value.DefaultCastAs(LogicalType::UBIGINT);
  if (casted.IsNull()) {
    throw IOException("Column %s cannot be NULL", name);
  }
  return casted.GetValue<uint64_t>();
}

static void PcapngListCopyOptions(ClientContext &context,
                                  CopyOptionsInput &input) {
  input.options["mode"] =
      CopyOption(LogicalType::VARCHAR, CopyOptionMode::WRITE_ONLY);
  input.options["linktype"] =
      CopyOption(LogicalType::UINTEGER, CopyOptionMode::WRITE_ONLY);
}

static unique_ptr<FunctionData>
PcapngWriteBind(ClientContext &context, CopyFunctionBindInput &input,
                const vector<string> &names,
                const vector<LogicalType> &sql_types) {
  auto bind_data = make_uniq<PqcapCopyBindData>();
  for (auto it = input.info.options.begin(); it != input.info.options.end();
       ++it) {
    const string option = StringUtil::Lower(it->first);
    if (it->second.size() != 1) {
      throw BinderException("COPY option \"%s\" expects exactly one value",
                            option);
    }
    if (option == "mode") {
      if (it->second[0].type().id() != LogicalTypeId::VARCHAR) {
        throw BinderException("mode must be VARCHAR");
      }
      bind_data->mode = StringUtil::Lower(it->second[0].GetValue<string>());
      if (bind_data->mode != "pcapng" && bind_data->mode != "pqcap") {
        throw BinderException("mode must be 'pcapng' or 'pqcap'");
      }
    } else if (option == "linktype") {
      uint64_t v = ParseUInt64(it->second[0], "linktype");
      if (v > 65535ULL) {
        throw BinderException("linktype must fit in uint16");
      }
      bind_data->linktype = static_cast<uint16_t>(v);
    } else {
      throw BinderException(
          "Unrecognized option for COPY (FORMAT pcapng): \"%s\"", option);
    }
  }

  bind_data->idx_timestamp_micros = FindColumnIdx(names, "timestamp_micros");
  bind_data->idx_orig_len = FindColumnIdx(names, "orig_len");
  bind_data->idx_payload = FindColumnIdx(names, "payload");
  bind_data->idx_src_ip = FindColumnIdx(names, "src_ip");
  bind_data->idx_dst_ip = FindColumnIdx(names, "dst_ip");
  bind_data->idx_src_port = FindColumnIdx(names, "src_port");
  bind_data->idx_dst_port = FindColumnIdx(names, "dst_port");
  bind_data->idx_protocols = FindColumnIdx(names, "protocols");
  if (bind_data->idx_protocols == DConstants::INVALID_INDEX) {
    bind_data->idx_protocols = FindColumnIdx(names, "l4_protocol");
  }
  if (bind_data->idx_payload == DConstants::INVALID_INDEX ||
      sql_types[bind_data->idx_payload].id() != LogicalTypeId::BLOB) {
    throw BinderException(
        "COPY (FORMAT pcapng) requires a BLOB payload column");
  }
  if (bind_data->idx_timestamp_micros == DConstants::INVALID_INDEX) {
    throw BinderException("COPY (FORMAT pcapng) requires timestamp_micros");
  }
  if (bind_data->idx_orig_len == DConstants::INVALID_INDEX) {
    throw BinderException("COPY (FORMAT pcapng) requires orig_len");
  }
  return std::move(bind_data);
}

static unique_ptr<GlobalFunctionData>
PcapngWriteInitializeGlobal(ClientContext &context, FunctionData &bind_data,
                            const string &file_path) {
  auto &cfg = bind_data.Cast<PqcapCopyBindData>();
  auto *file_info = light_create_default_file_info();
  if (!file_info) {
    throw IOException("LightPcapNg file info allocation failed");
  }
  file_info->interface_block_count = 1;
  file_info->link_types[0] = cfg.linktype;

  auto *writer = light_pcapng_open_write(file_path.c_str(), file_info, 0);
  if (!writer) {
    light_free_file_info(file_info);
    throw IOException("Failed opening output file %s", file_path);
  }
  auto result = make_uniq<PqcapCopyGlobalState>();
  result->writer = writer;
  result->output_path = file_path;
  return std::move(result);
}

static unique_ptr<LocalFunctionData>
PcapngWriteInitializeLocal(ExecutionContext &context, FunctionData &bind_data) {
  return make_uniq<LocalFunctionData>();
}

static void PcapngWriteSink(ExecutionContext &context, FunctionData &bind_data,
                            GlobalFunctionData &gstate,
                            LocalFunctionData &lstate, DataChunk &input) {
  auto &cfg = bind_data.Cast<PqcapCopyBindData>();
  auto &state = gstate.Cast<PqcapCopyGlobalState>();
  std::lock_guard<std::mutex> guard(state.lock);

  for (idx_t r = 0; r < input.size(); r++) {
    PacketRowData row;
    row.ts_micros = ParseUInt64(input.GetValue(cfg.idx_timestamp_micros, r),
                                "timestamp_micros");
    row.orig_len = ParseUInt64(input.GetValue(cfg.idx_orig_len, r), "orig_len");
    Value payload = input.GetValue(cfg.idx_payload, r);
    if (payload.IsNull()) {
      throw IOException("payload cannot be NULL");
    }
    row.packet_bytes = payload.GetValue<string>();

    if (cfg.idx_src_ip != DConstants::INVALID_INDEX) {
      Value v = input.GetValue(cfg.idx_src_ip, r);
      if (!v.IsNull()) {
        row.src_ip = v.GetValue<string>();
      }
    }
    if (cfg.idx_dst_ip != DConstants::INVALID_INDEX) {
      Value v = input.GetValue(cfg.idx_dst_ip, r);
      if (!v.IsNull()) {
        row.dst_ip = v.GetValue<string>();
      }
    }
    if (cfg.idx_src_port != DConstants::INVALID_INDEX) {
      Value v = input.GetValue(cfg.idx_src_port, r);
      if (!v.IsNull()) {
        row.src_port = static_cast<uint32_t>(ParseUInt64(v, "src_port"));
        row.has_src_port = true;
      }
    }
    if (cfg.idx_dst_port != DConstants::INVALID_INDEX) {
      Value v = input.GetValue(cfg.idx_dst_port, r);
      if (!v.IsNull()) {
        row.dst_port = static_cast<uint32_t>(ParseUInt64(v, "dst_port"));
        row.has_dst_port = true;
      }
    }
    if (cfg.idx_protocols != DConstants::INVALID_INDEX) {
      Value v = input.GetValue(cfg.idx_protocols, r);
      if (!v.IsNull()) {
        row.protocols = StringUtil::Lower(v.GetValue<string>());
      }
    }

    light_packet_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.interface_id = 0;
    hdr.data_link = cfg.linktype;
    hdr.captured_length = static_cast<uint32_t>(row.packet_bytes.size());
    hdr.original_length = static_cast<uint32_t>(row.orig_len);
    hdr.timestamp.tv_sec = static_cast<time_t>(row.ts_micros / 1000000ULL);
    hdr.timestamp.tv_nsec =
        static_cast<long>((row.ts_micros % 1000000ULL) * 1000ULL);
    light_write_packet(
        state.writer, &hdr,
        reinterpret_cast<const uint8_t *>(row.packet_bytes.data()));
    state.rows.push_back(row);
  }
}

static void PcapngWriteCombine(ExecutionContext &context,
                               FunctionData &bind_data,
                               GlobalFunctionData &gstate,
                               LocalFunctionData &lstate) {}

static uint32_t ReadLE32(const uint8_t *ptr) {
  return static_cast<uint32_t>(ptr[0]) | (static_cast<uint32_t>(ptr[1]) << 8) |
         (static_cast<uint32_t>(ptr[2]) << 16) |
         (static_cast<uint32_t>(ptr[3]) << 24);
}

static std::vector<PacketLocation>
ScanPacketLocations(const string &pcap_path) {
  std::vector<PacketLocation> out;
  FILE *f = std::fopen(pcap_path.c_str(), "rb");
  if (!f) {
    throw IOException("Failed opening output file for offset scan");
  }
  std::fseek(f, 0, SEEK_END);
  const size_t size = static_cast<size_t>(std::ftell(f));
  std::fseek(f, 0, SEEK_SET);
  std::vector<uint8_t> data(size);
  if (size && std::fread(data.data(), 1, size, f) != size) {
    std::fclose(f);
    throw IOException("Failed reading output file for offset scan");
  }
  std::fclose(f);

  size_t pos = 0;
  while (pos + 12 <= data.size()) {
    const uint32_t block_type = ReadLE32(data.data() + pos);
    const uint32_t total_len = ReadLE32(data.data() + pos + 4);
    if (total_len < 12 || pos + total_len > data.size()) {
      break;
    }
    if (block_type == 0x00000006 && total_len >= 32) {
      const uint32_t captured_len = ReadLE32(data.data() + pos + 8 + 12);
      out.push_back(PacketLocation{static_cast<uint64_t>(pos + 28),
                                   static_cast<uint64_t>(captured_len)});
    } else if (block_type == 0x00000003 && total_len >= 16) {
      const uint32_t pkt_len = ReadLE32(data.data() + pos + 8);
      out.push_back(PacketLocation{static_cast<uint64_t>(pos + 12),
                                   static_cast<uint64_t>(pkt_len)});
    }
    pos += total_len;
  }
  return out;
}

static string SqlEscape(const string &s) {
  return StringUtil::Replace(s, "'", "''");
}

static void WriteMetadataParquetViaSQL(const string &parquet_path,
                                       const std::vector<PacketRowData> &rows,
                                       const std::vector<PacketLocation> &locs,
                                       uint16_t linktype) {
  if (rows.size() != locs.size()) {
    throw IOException(
        "pqcap writer mismatch between packet rows and written packet blocks");
  }
  const string table_name =
      "tmp_pqcap_writer_" + std::to_string(reinterpret_cast<uintptr_t>(&rows));
  DuckDB temp_db(nullptr);
  Connection con(temp_db);
  auto res = con.Query("LOAD parquet");
  if (res->HasError()) {
    throw IOException("Failed loading parquet extension in temp writer DB: %s",
                      res->GetError());
  }
  res = con.Query("CREATE TEMP TABLE " + table_name +
                  "(frame_number UBIGINT, ts_ns UBIGINT, protocols "
                  "VARCHAR, src_ip VARCHAR, src_port UINTEGER, "
                  "dst_ip VARCHAR, dst_port UINTEGER, \"offset\" UBIGINT, "
                  "\"size\" UBIGINT, linktype UINTEGER)");
  if (res->HasError()) {
    throw IOException("Failed creating temp metadata table: %s",
                      res->GetError());
  }
  if (!rows.empty()) {
    string insert_sql = "INSERT INTO " + table_name + " VALUES ";
    for (idx_t i = 0; i < rows.size(); i++) {
      if (i > 0) {
        insert_sql += ",";
      }
      insert_sql += "(" + std::to_string(i + 1) + "," +
                    std::to_string(rows[i].ts_micros * 1000ULL) + ",'";
      insert_sql +=
          SqlEscape(rows[i].protocols.empty() ? "unknown" : rows[i].protocols) +
          "',";
      insert_sql += rows[i].src_ip.empty()
                        ? "NULL"
                        : "'" + SqlEscape(rows[i].src_ip) + "'";
      insert_sql += ",";
      insert_sql +=
          rows[i].has_src_port ? std::to_string(rows[i].src_port) : "NULL";
      insert_sql += ",";
      insert_sql += rows[i].dst_ip.empty()
                        ? "NULL"
                        : "'" + SqlEscape(rows[i].dst_ip) + "'";
      insert_sql += ",";
      insert_sql +=
          rows[i].has_dst_port ? std::to_string(rows[i].dst_port) : "NULL";
      insert_sql += ",";
      insert_sql += std::to_string(locs[i].offset) + "," +
                    std::to_string(locs[i].size) + "," +
                    std::to_string(static_cast<uint32_t>(linktype)) + ")";
    }
    res = con.Query(insert_sql);
    if (res->HasError()) {
      throw IOException("Failed inserting pqcap metadata rows: %s",
                        res->GetError());
    }
  }
  res = con.Query("COPY " + table_name + " TO '" + SqlEscape(parquet_path) +
                  "' (FORMAT parquet)");
  if (res->HasError()) {
    throw IOException("Failed writing embedded parquet metadata: %s",
                      res->GetError());
  }
  con.Query("DROP TABLE " + table_name);
}

static void WriteLE16(std::vector<uint8_t> &buf, uint16_t v) {
  buf.push_back(static_cast<uint8_t>(v & 0xff));
  buf.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
}
static void WriteLE32(std::vector<uint8_t> &buf, uint32_t v) {
  buf.push_back(static_cast<uint8_t>(v & 0xff));
  buf.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
  buf.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
  buf.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
}
static void WriteLE64(std::vector<uint8_t> &buf, uint64_t v) {
  for (int i = 0; i < 8; i++) {
    buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xff));
  }
}

static std::vector<uint8_t> ReadFileBytes(const string &path) {
  FILE *f = std::fopen(path.c_str(), "rb");
  if (!f) {
    throw IOException("Failed opening %s", path);
  }
  std::fseek(f, 0, SEEK_END);
  size_t size = static_cast<size_t>(std::ftell(f));
  std::fseek(f, 0, SEEK_SET);
  std::vector<uint8_t> out(size);
  if (size && std::fread(out.data(), 1, size, f) != size) {
    std::fclose(f);
    throw IOException("Failed reading %s", path);
  }
  std::fclose(f);
  return out;
}

static void WriteFileBytes(const string &path,
                           const std::vector<uint8_t> &bytes) {
  FILE *f = std::fopen(path.c_str(), "wb");
  if (!f) {
    throw IOException("Failed opening %s for write", path);
  }
  if (!bytes.empty() &&
      std::fwrite(bytes.data(), 1, bytes.size(), f) != bytes.size()) {
    std::fclose(f);
    throw IOException("Failed writing %s", path);
  }
  std::fclose(f);
}

static void EmbedParquetInPqcap(const string &pcap_path,
                                const string &parquet_path) {
  auto capture = ReadFileBytes(pcap_path);
  auto parquet = ReadFileBytes(parquet_path);

  std::vector<uint8_t> body;
  WriteLE32(body, PQCAP_ENTERPRISE_ID);
  for (idx_t i = 0; i < 9; i++) {
    body.push_back(static_cast<uint8_t>(PQCAP_MAGIC[i]));
  }
  WriteLE16(body, 1);
  WriteLE16(body, 0);
  WriteLE64(body, parquet.size());
  body.insert(body.end(), parquet.begin(), parquet.end());
  while ((body.size() % 4) != 0) {
    body.push_back(0);
  }

  std::vector<uint8_t> custom_block;
  uint32_t custom_len = static_cast<uint32_t>(12 + body.size());
  WriteLE32(custom_block, PQCAP_CUSTOM_BLOCK_TYPE);
  WriteLE32(custom_block, custom_len);
  custom_block.insert(custom_block.end(), body.begin(), body.end());
  WriteLE32(custom_block, custom_len);

  uint64_t parquet_abs_offset = static_cast<uint64_t>(capture.size()) + 8 + 25;
  std::vector<uint8_t> footer_body;
  WriteLE32(footer_body, PQCAP_ENTERPRISE_ID);
  for (idx_t i = 0; i < 8; i++) {
    footer_body.push_back(static_cast<uint8_t>(PQCAP_FOOTER_MAGIC[i]));
  }
  WriteLE16(footer_body, 1);
  WriteLE16(footer_body, 0);
  WriteLE64(footer_body, parquet_abs_offset);
  WriteLE64(footer_body, parquet.size());

  std::vector<uint8_t> footer_block;
  uint32_t footer_len = static_cast<uint32_t>(12 + footer_body.size());
  WriteLE32(footer_block, PQCAP_FOOTER_BLOCK_TYPE);
  WriteLE32(footer_block, footer_len);
  footer_block.insert(footer_block.end(), footer_body.begin(),
                      footer_body.end());
  WriteLE32(footer_block, footer_len);

  capture.insert(capture.end(), custom_block.begin(), custom_block.end());
  capture.insert(capture.end(), footer_block.begin(), footer_block.end());
  WriteFileBytes(pcap_path, capture);
}

static void PcapngWriteFinalize(ClientContext &context, FunctionData &bind_data,
                                GlobalFunctionData &gstate) {
  auto &cfg = bind_data.Cast<PqcapCopyBindData>();
  auto &state = gstate.Cast<PqcapCopyGlobalState>();
  std::lock_guard<std::mutex> guard(state.lock);
  if (state.writer) {
    light_pcapng_close(state.writer);
    state.writer = nullptr;
  }
  if (cfg.mode != "pqcap") {
    return;
  }
  auto locations = ScanPacketLocations(state.output_path);
  const string temp_parquet = state.output_path + ".tmp.meta.parquet";
  WriteMetadataParquetViaSQL(temp_parquet, state.rows, locations, cfg.linktype);
  EmbedParquetInPqcap(state.output_path, temp_parquet);
  std::remove(temp_parquet.c_str());
}

} // namespace

void RegisterPqcapCopyFunction(ExtensionLoader &loader) {
  CopyFunction function("pcapng");
  function.copy_options = PcapngListCopyOptions;
  function.copy_to_bind = PcapngWriteBind;
  function.copy_to_initialize_global = PcapngWriteInitializeGlobal;
  function.copy_to_initialize_local = PcapngWriteInitializeLocal;
  function.copy_to_sink = PcapngWriteSink;
  function.copy_to_combine = PcapngWriteCombine;
  function.copy_to_finalize = PcapngWriteFinalize;
  function.extension = "pcapng";
  loader.RegisterFunction(function);
}

} // namespace duckdb
