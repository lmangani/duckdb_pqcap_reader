# duckdb_pqcap_reader

DuckDB extension workspace for reading `.pqcapng` directly.

## Goal

Expose a table function:

```sql
SELECT * FROM read_pqcap('capture.pqcapng');
```

without requiring metadata extraction to separate files.

## Scope

### Phase 1 (local files)

- Parse fixed footer locator from `.pqcapng`
- Read embedded Parquet bytes only
- Return metadata rows as DuckDB table result

### Phase 2 (remote/object URLs)

- Footer range-read (`bytes=-44`)
- Metadata range-read (offset/length from footer)
- Push down projections/filters into Parquet scan path

## SQL API target

```sql
SELECT *
FROM read_pqcap('capture.pqcapng');
```

Optional parameters (planned):

- `gdal_vsi := true|false`
- `validate := true|false`

## Development notes

This repository is currently scaffolded for implementation planning and code bring-up.
See `docs/IMPLEMENTATION_PLAN.md`.
