#include "pqcap_footer.h"

#include "duckdb.hpp"
#include "duckdb/main/extension_util.hpp"

namespace duckdb {

static void PqcapVersionFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    result.SetVectorType(VectorType::CONSTANT_VECTOR);
    Value v("duckdb_pqcap_reader-dev");
    ConstantVector::SetData(result, v);
}

static void LoadInternal(DatabaseInstance &instance) {
    ScalarFunctionSet set("pqcap_reader_version");
    set.AddFunction(ScalarFunction({}, LogicalType::VARCHAR, PqcapVersionFunction));
    ExtensionUtil::RegisterFunction(instance, set);
}

void PqcapReaderExtensionInit(DatabaseInstance &db) {
    LoadInternal(db);
}

const char *PqcapReaderExtensionVersion() {
    return DuckDB::LibraryVersion();
}

} // namespace duckdb

extern "C" {

DUCKDB_EXTENSION_API void pqcap_reader_init(duckdb::DatabaseInstance &db) {
    duckdb::PqcapReaderExtensionInit(db);
}

DUCKDB_EXTENSION_API const char *pqcap_reader_version() {
    return duckdb::PqcapReaderExtensionVersion();
}
}
