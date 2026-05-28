## Implementation plan

## 1) Footer parser (must-have)

Implement a parser for the fixed final custom block:

- block type: footer locator block type
- fixed total length: 44
- body fields:
  - enterprise id
  - magic `PQCAPFTR`
  - version
  - metadata Parquet offset
  - metadata Parquet length

Validation checks:

- full footer block length is present
- trailing block length matches leading block length
- offset+length bounds check with overflow protection

## 2) Metadata reader (must-have)

- local file read path:
  - seek to footer
  - parse locator
  - read exact Parquet byte slice

## 3) Table function wiring

Define:

- `read_pqcap(path VARCHAR)` table function

Output schema:

- required columns from metadata Parquet (`offset`, `size`, `ts_ns`, `linktype`)
- optional passthrough columns (SIP/flow fields)

## 4) Remote range-read path (next)

- URL scheme detection (`http://`, `https://`, `s3://`, etc. based on DuckDB runtime support)
- suffix range read for footer
- bounded range read for metadata bytes

## 5) Tests

- valid local `.pqcapng` sample reads
- invalid footer cases fail cleanly
- missing metadata block fails cleanly
- large-index smoke (>= 1k rows)
