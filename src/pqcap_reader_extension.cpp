#define DUCKDB_EXTENSION_MAIN

#include "pqcap_reader_extension.hpp"
#include "pqcap_copy_function.hpp"
#include "pqcap_duckdb_compat.hpp"
#include "pqcap_footer.h"
#include "pqcap_packet_table.hpp"
#include "pqcap_subfile_fs.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/function/replacement_scan.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/parsed_data/create_macro_info.hpp"
#include "duckdb/parser/statement/create_statement.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"

#include <vector>

namespace duckdb {

static constexpr idx_t PQCAP_FOOTER_BLOCK_SIZE = 44;

static std::string ParsePqcapMetadataLocation(FileHandle &handle,
                                              const std::string &source) {
  auto file_size = (idx_t)handle.GetFileSize();
  if (file_size < PQCAP_FOOTER_BLOCK_SIZE) {
    throw InvalidInputException("pqcap file too small: " + source);
  }
  std::vector<char> tail(PQCAP_FOOTER_BLOCK_SIZE);
  handle.Read(tail.data(), PQCAP_FOOTER_BLOCK_SIZE,
              file_size - PQCAP_FOOTER_BLOCK_SIZE);

  pqcap_reader::FooterLocator loc;
  if (!pqcap_reader::ParseFooterLocator(std::string(tail.data(), tail.size()),
                                        loc)) {
    throw InvalidInputException("invalid pqcap footer locator: " + source);
  }
  if (loc.parquet_length == 0) {
    throw InvalidInputException("pqcap embedded metadata length is zero: " +
                                source);
  }
  if (loc.parquet_offset + loc.parquet_length < loc.parquet_offset ||
      loc.parquet_offset + loc.parquet_length > file_size) {
    throw InvalidInputException("pqcap footer offset/length out of range: " +
                                source);
  }
  return std::to_string(loc.parquet_offset) + "_" +
         std::to_string(loc.parquet_length);
}

template <typename Body>
static void StringScalarLoop(DataChunk &args, Vector &result, const char *fn,
                             Body body) {
  auto count = args.size();
  pqcap_compat::FlattenVector(args.data[0], count);
  auto &src_valid = FlatVector::Validity(args.data[0]);
  result.SetVectorType(VectorType::FLAT_VECTOR);
  auto src = pqcap_compat::FlatVectorGetData<string_t>(args.data[0]);

  for (idx_t i = 0; i < count; i++) {
    if (!src_valid.RowIsValid(i)) {
      throw InvalidInputException(std::string(fn) + ": path argument is NULL");
    }
    result.SetValue(i, Value(body(std::string(src[i].GetString()))));
  }
}

static void PqcapOffsetSizeFunction(DataChunk &args, ExpressionState &state,
                                    Vector &result) {
  auto &fs = FileSystem::GetFileSystem(state.GetContext());
  StringScalarLoop(
      args, result, "pqcap_offset_size", [&](const std::string &path) {
        auto handle = fs.OpenFile(path, FileFlags::FILE_FLAGS_READ);
        if (!handle) {
          throw IOException("pqcap_offset_size: could not open " + path);
        }
        return ParsePqcapMetadataLocation(*handle, path);
      });
}

static const char *kReadPqcapMacro = R"sql(
CREATE OR REPLACE MACRO read_pqcap(p) AS TABLE
SELECT *
FROM read_parquet('pqcap-subfile://' || pqcap_offset_size(p) || '!' || p);
)sql";

static unique_ptr<TableRef>
PqcapReaderReplacementScan(ClientContext &context, ReplacementScanInput &input,
                           optional_ptr<ReplacementScanData> data) {
  auto table_name = ReplacementScan::GetFullPath(input);
  const char *function_name = nullptr;
  if (ReplacementScan::CanReplace(table_name, {"pqcap", "pqcapng"})) {
    function_name = "read_pqcap";
  } else if (ReplacementScan::CanReplace(table_name, {"pcap", "pcapng"})) {
    function_name = "read_pqcap_packets";
  } else {
    return nullptr;
  }

  auto table_function = make_uniq<TableFunctionRef>();
  vector<unique_ptr<ParsedExpression>> children;
  children.push_back(make_uniq<ConstantExpression>(Value(table_name)));
  table_function->function =
      make_uniq<FunctionExpression>(function_name, std::move(children));

  if (!FileSystem::HasGlob(table_name)) {
    auto &fs = FileSystem::GetFileSystem(context);
    table_function->alias = fs.ExtractBaseName(table_name);
  }
  return std::move(table_function);
}

static void LoadInternal(ExtensionLoader &loader) {
  auto &db = loader.GetDatabaseInstance();
  db.GetFileSystem().RegisterSubSystem(make_uniq<PqcapSubFileSystem>());

  ScalarFunction offset_size_fn("pqcap_offset_size", {LogicalType::VARCHAR},
                                LogicalType::VARCHAR, PqcapOffsetSizeFunction);
  loader.RegisterFunction(offset_size_fn);
  RegisterPqcapPacketTableFunction(loader);
  RegisterPqcapCopyFunction(loader);

  Parser parser;
  parser.ParseQuery(kReadPqcapMacro);
  if (parser.statements.empty()) {
    throw IOException("pqcap: read_pqcap macro SQL produced no statements");
  }
  auto &create_stmt = static_cast<CreateStatement &>(*parser.statements[0]);
  auto &macro_info = static_cast<CreateMacroInfo &>(*create_stmt.info);
  macro_info.schema = "main";
  macro_info.internal = true;
  loader.RegisterFunction(macro_info);

  auto &config = DBConfig::GetConfig(db);
  config.replacement_scans.emplace_back(PqcapReaderReplacementScan);
}

void PqcapReaderExtension::Load(ExtensionLoader &loader) {
  LoadInternal(loader);
}

std::string PqcapReaderExtension::Name() { return "pqcap_reader"; }

std::string PqcapReaderExtension::Version() const {
#ifdef EXT_VERSION_PQCAP_READER
  return EXT_VERSION_PQCAP_READER;
#else
  return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(pqcap_reader, loader) {
  duckdb::LoadInternal(loader);
}
}
