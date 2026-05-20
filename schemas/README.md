# Machine-Readable Output Schemas

This directory documents the machine-readable files emitted by `download_js_map_files`.

| File | Schema |
|------|--------|
| `summary.json` | [`summary.schema.json`](summary.schema.json) |
| `artifact_manifest.json` | [`artifact-manifest.schema.json`](artifact-manifest.schema.json) |
| `scope_report.json` | [`scope-report.schema.json`](scope-report.schema.json) |
| `endpoints.jsonl` | [`endpoint-record.schema.json`](endpoint-record.schema.json), one JSON object per line |
| `findings.jsonl` | [`secret-finding-record.schema.json`](secret-finding-record.schema.json), one JSON object per line |

The JSONL files are append-only record streams. Validate each non-empty line as a standalone JSON object.
