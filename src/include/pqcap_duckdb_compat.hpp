#pragma once

#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/common/types/vector.hpp"

#if defined(__has_include)
#if __has_include("duckdb/common/vector/flat_vector.hpp")
#include "duckdb/common/vector/flat_vector.hpp"
#define PQCAP_DUCKDB_HAS_FLAT_VECTOR_HPP 1
#endif
#if __has_include("duckdb/common/vector/string_vector.hpp")
#include "duckdb/common/vector/string_vector.hpp"
#endif
#endif

#ifndef PQCAP_DUCKDB_HAS_FLAT_VECTOR_HPP
#define PQCAP_DUCKDB_HAS_FLAT_VECTOR_HPP 0
#endif

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

template <class T>
inline T *FlatVectorGetData(Vector &vector) {
#if PQCAP_DUCKDB_HAS_FLAT_VECTOR_HPP
  return FlatVector::GetDataMutable<T>(vector);
#else
  return FlatVector::GetData<T>(vector);
#endif
}

} // namespace pqcap_compat
} // namespace duckdb
