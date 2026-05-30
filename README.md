<img width="300" alt="pqcap" src="https://github.com/user-attachments/assets/bcc8c286-1d67-4c5e-baa9-6e7342709879" />

# DuckDB PQCAP Reader Extension

DuckDB extension for the [pqcap](https://github.com/sipcapture/pqcap) hybrid capture format: **PCAP-NG packet plane** plus **embedded Parquet metadata**, queryable in SQL without extracting sidecar files.

## Features

- **Metadata plane** — `read_pqcap(path)` reads embedded Parquet via a footer locator and `pqcap-subfile://` range reads (local files today; object-store friendly layout).
- **Packet plane** — `read_pqcap_packets(path)` reads **classic `.pcap` and `.pcapng`** via LightPcapNg (plus a native classic PCAP reader), exposing capture headers and full frame bytes as `payload` BLOB.
- **Path shorthand** — DuckDB [replacement scans](https://duckdb.org/docs/stable/clients/cli/overview.html) route quoted paths by suffix (extension must be loaded):

  | Suffix | Reader |
  |--------|--------|
  | `.pqcap`, `.pqcapng` | `read_pqcap` (metadata) |
  | `.pcap`, `.pcapng` | `read_pqcap_packets` (packets) |

- **Writer** — `COPY ... (FORMAT pcapng)` with `mode 'pcapng'` (packets only) or `mode 'pqcap'` (packets + index).
- **Indexer** — `pqcap_embed_index(path)` embeds searchable metadata on an existing capture (no payload round-trip; used by `pqcap convert`).

Internals:

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

Embedded Parquet holds **search features only** — not packet payloads.

```sql
SELECT frame_number, protocols, src_ip, dst_port, "offset", "size"
FROM read_pqcap('capture.pqcapng');
```

Shorthand:

```sql
SELECT * FROM 'capture.pqcapng';
```

Reference optional columns: `frame_number`, `protocols`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `interface_id`, `data_link`, `captured_length`, `orig_len`, `comment` (plus required `offset`, `size`, `ts_ns`, `linktype`).

### Packets (capture plane)

```sql
SELECT timestamp_micros, interface_id, data_link, captured_length, orig_len, comment,
       src_ip, dst_ip, src_port, dst_port, l4_protocol, payload
FROM read_pqcap_packets('capture.pcapng')
WHERE l4_protocol = 'UDP' AND src_port = 5060;
```

Shorthand:

```sql
SELECT * FROM 'capture.pcapng' WHERE l4_protocol = 'UDP';
```

### Cross-plane (filter index, read payloads)

```sql
WITH hits AS (
  SELECT src_ip, src_port, dst_ip, dst_port
  FROM read_pqcap('capture.pqcapng')
  WHERE dst_port = 443
)
SELECT p.timestamp_micros, p.payload
FROM read_pqcap_packets('capture.pqcapng') AS p
JOIN hits USING (src_ip, src_port, dst_ip, dst_port)
LIMIT 10;
```

### Write captures

Packet-only PCAP-NG:

```sql
COPY (
  SELECT timestamp_micros, orig_len, payload, src_ip, src_port, dst_ip, dst_port, l4_protocol
  FROM read_pqcap_packets('in.pqcapng')
) TO 'out.pcapng' (FORMAT pcapng, mode 'pcapng');
```

PQCAP bundle (repack + index — `payload` required for EPB write; Parquet stores features only):

```sql
COPY (
  SELECT timestamp_micros, interface_id, data_link, captured_length, orig_len, comment,
         src_ip, src_port, dst_ip, dst_port, l4_protocol, payload
  FROM read_pqcap_packets('in.pqcapng')
) TO 'out.pqcapng' (FORMAT pcapng, mode 'pqcap');
```

Index an existing capture in place (`pqcap convert` uses this):

```sql
SELECT pqcap_embed_index('capture.pcapng');  -- returns packet count
```

## Repository layout

This repo follows the [DuckDB extension template](https://github.com/duckdb/extension-template):

- `duckdb` submodule
- `extension-ci-tools` submodule
- `Makefile`, `extension_config.cmake`, `description.yml`
- SQL tests under `test/sql`
- Sample captures under `test/data/`

Initialize submodules:

```bash
git submodule update --init --recursive
```

## Build and test

```bash
make release
./build/release/test/unittest test/sql/pqcap_reader.test
```

Interactive shell:

```bash
./build/release/duckdb -unsigned
```

```sql
LOAD pqcap_reader;
SELECT * FROM 'test/data/demo.pqcapng';
SELECT count(*) FROM read_pqcap_packets('test/data/aaa.pcap') WHERE l4_protocol = 'UDP';
```

## Related

- Format spec and tooling: [sipcapture/pqcap](https://github.com/sipcapture/pqcap)
- Implementation notes: `docs/IMPLEMENTATION_PLAN.md`
