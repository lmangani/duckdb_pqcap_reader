# duckdb_pqcap_reader

DuckDB extension workspace for reading `.pqcapng` directly.

The extension structure follows the same proven pattern used by production DuckDB format readers:

- custom subfile virtual filesystem for bounded byte ranges
- scalar locator function (`pqcap_offset_size`)
- SQL macro table function (`read_pqcap`) composed over `read_parquet(...)`

## Template compliance

This repository follows the official DuckDB extension-template layout, including:

- `duckdb` submodule
- `extension-ci-tools` submodule
- `Makefile`, `extension_config.cmake`, `description.yml`
- SQL tests under `test/sql`

Initialize submodules:

```bash
git submodule update --init --recursive
```

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

Build locally:

```bash
make release
```

Run SQL tests:

```bash
make test
```

Use local unsigned extension:

```bash
./build/release/duckdb -unsigned
```

Inside DuckDB:

```sql
SELECT * FROM read_pqcap('test/data/demo.pqcapng');
```

See `docs/IMPLEMENTATION_PLAN.md` for roadmap details.
