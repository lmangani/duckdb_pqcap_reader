#pragma once

#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

void RegisterPqcapPacketTableFunction(ExtensionLoader &loader);

} // namespace duckdb
