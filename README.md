<img width="300" alt="pqcap" src="https://github.com/user-attachments/assets/bcc8c286-1d67-4c5e-baa9-6e7342709879" />

# DuckDB PQCAP Reader Extension

DuckDB extension for the [pqcap](https://github.com/sipcapture/pqcap) hybrid capture format: **PCAP-NG packet plane** plus **embedded Parquet metadata**, queryable in SQL without extracting sidecar files.

## Features

- **Metadata plane** — `read_pqcap(path)` reads embedded Parquet via a footer locator and `pqcap-subfile://` range reads (local files today; object-store friendly layout).
- **Packet plane** — `read_pqcap_packets(path)` decodes PCAP-NG records (IPs, ports, L4 protocol, payload blob) with LightPcapNg.
- **Path shorthand** — DuckDB [replacement scans](https://duckdb.org/docs/stable/clients/cli/overview.html) route quoted paths by suffix (extension must be loaded):

  | Suffix | Reader |
  |--------|--------|
  | `.pqcap`, `.pqcapng` | `read_pqcap` (metadata) |
  | `.pcap`, `.pcapng` | `read_pqcap_packets` (packets) |

- **Writer** — `COPY ... TO 'out.pcapng' (FORMAT pcapng, mode 'pcapng' \| 'pqcap')` for packet-only or pqcap bundles with embedded metadata.

Internals follow the same pattern as production DuckDB format readers:

- `PqcapSubFileSystem` for bounded byte-range reads
- `pqcap_offset_size(path)` scalar locator
- `read_pqcap` SQL macro over `read_parquet('pqcap-subfile://…')`

## Install and load

```sql
-- community or custom repository when published
INSTALL pqcap_reader FROM community;
LOAD pqcap_reader;
```

For local development builds, load the artifact from `build/release/extension/pqcap_reader/` (DuckDB version must match the extension binary).

`read_pqcap` depends on the **parquet** extension; enable parquet (or autoload) in the same session.

## SQL usage

### Metadata (Parquet plane)

```sql
SELECT *
FROM read_pqcap('capture.pqcapng');
```

Shorthand (same as above when `pqcap_reader` is loaded):

```sql
SELECT *
FROM 'capture.pqcapng';
```

### Packets (PCAP-NG plane)

```sql
SELECT timestamp_micros, src_ip, dst_ip, src_port, dst_port, l4_protocol, orig_len, payload
FROM read_pqcap_packets('capture.pqcapng')
WHERE l4_protocol = 'UDP' AND src_port = 5060;
```

Shorthand for standard capture suffixes:

```sql
SELECT *
FROM 'capture.pcapng'
WHERE l4_protocol = 'UDP';
```

### Write captures

Packet-only PCAP-NG:

```sql
COPY (
  SELECT timestamp_micros, orig_len, payload, src_ip, src_port, dst_ip, dst_port, l4_protocol
  FROM read_pqcap_packets('in.pqcapng')
) TO 'out.pcapng' (FORMAT pcapng, mode 'pcapng');
```

PQCAP bundle (packets + embedded metadata):

```sql
COPY (
  SELECT timestamp_micros, orig_len, payload, src_ip, src_port, dst_ip, dst_port, l4_protocol
  FROM read_pqcap_packets('in.pqcapng')
) TO 'out.pqcapng' (FORMAT pcapng, mode 'pqcap');
```

## Repository layout

This repo follows the [DuckDB extension template](https://github.com/duckdb/extension-template):

- `duckdb` submodule
- `extension-ci-tools` submodule
- `Makefile`, `extension_config.cmake`, `description.yml`
- SQL tests under `test/sql`

Initialize submodules:

```bash
git submodule update --init --recursive
```

## Build and test

```bash
make release
```

Run extension SQL tests (preferred — avoids the full DuckDB `unittest` matrix):

```bash
./build/release/test/unittest test/sql/pqcap_reader.test
```

Interactive shell:

```bash
./build/release/duckdb -unsigned
```

```sql
LOAD pqcap_reader;  -- omit when extension is statically linked into your build
SELECT * FROM 'test/data/demo.pqcapng';
SELECT * FROM read_pqcap_packets('test/data/demo.pqcapng') WHERE l4_protocol = 'UDP';
```

## Related

- Format spec and tooling: [sipcapture/pqcap](https://github.com/sipcapture/pqcap)
- Implementation notes: `docs/IMPLEMENTATION_PLAN.md`
