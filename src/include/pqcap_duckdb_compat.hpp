#pragma once

#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/common/types/vector.hpp"

namespace duckdb {
namespace pqcap_compat {

namespace detail {

template <typename V>
auto FlattenVectorImpl(V &vector, idx_t count,
                       decltype(vector.Flatten(), void()) *) -> void {
  vector.Flatten();
}

template <typename V>
auto FlattenVectorImpl(V &vector, idx_t count, ...) -> void {
  vector.Flatten(count);
}

template <typename C>
auto SetChunkValueImpl(C &chunk, idx_t col_idx, idx_t row_idx, const Value &val,
                       decltype(chunk.data[col_idx].SetValue(row_idx, val),
                                void()) *) -> void {
  chunk.data[col_idx].SetValue(row_idx, val);
}

template <typename C>
auto SetChunkValueImpl(C &chunk, idx_t col_idx, idx_t row_idx, const Value &val,
                       ...) -> void {
  chunk.SetValue(col_idx, row_idx, val);
}

} // namespace detail

inline void FlattenVector(Vector &vector, idx_t count) {
  detail::FlattenVectorImpl(vector, count, nullptr);
}

inline void SetChunkValue(DataChunk &chunk, idx_t col_idx, idx_t row_idx,
                          const Value &val) {
  detail::SetChunkValueImpl(chunk, col_idx, row_idx, val, nullptr);
}

} // namespace pqcap_compat
} // namespace duckdb
