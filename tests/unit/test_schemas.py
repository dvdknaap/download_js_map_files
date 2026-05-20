from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = PROJECT_ROOT / "schemas"


def load_schema(name: str) -> dict[str, Any]:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def test_machine_readable_output_schemas_are_parseable_and_linked() -> None:
    summary_schema = load_schema("summary.schema.json")
    manifest_schema = load_schema("artifact-manifest.schema.json")
    scope_schema = load_schema("scope-report.schema.json")
    endpoint_schema = load_schema("endpoint-record.schema.json")
    secret_schema = load_schema("secret-finding-record.schema.json")

    assert summary_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert manifest_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert scope_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert endpoint_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert secret_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert (SCHEMA_DIR / "README.md").exists()
    assert (SCHEMA_DIR / "secret-finding-record.schema.json").exists()


def test_summary_schema_documents_current_top_level_contract() -> None:
    schema = load_schema("summary.schema.json")

    assert set(schema["required"]) == {
        "target",
        "status",
        "proxy_enabled",
        "include_third_party",
        "scope_hosts",
        "exclude_hosts",
        "scope_report",
        "limits",
        "scripts",
        "files_written",
        "secret_findings",
        "endpoint_export",
        "counts",
    }
    status_schema = schema["properties"]["status"]
    assert set(status_schema["enum"]) == {
        "sourcemaps_found",
        "beautified_only",
        "no_scripts_found",
        "target_fetch_failed",
    }
    count_schema = schema["properties"]["counts"]
    assert "normalized_endpoints" in count_schema["required"]


def test_artifact_manifest_schema_documents_hash_contract() -> None:
    schema = load_schema("artifact-manifest.schema.json")

    assert set(schema["required"]) == {"schema_version", "generated_by", "artifact_count", "artifacts"}
    artifacts = schema["properties"]["artifacts"]
    artifact_record = artifacts["items"]
    assert set(artifact_record["required"]) == {"path", "size_bytes", "sha256"}
    assert artifact_record["properties"]["sha256"]["pattern"] == "^[0-9a-f]{64}$"


def test_scope_report_schema_documents_decision_reasons() -> None:
    schema = load_schema("scope-report.schema.json")
    decisions = schema["properties"]["decisions"]
    decision_record = decisions["items"]
    reason_schema = decision_record["properties"]["reason"]

    assert set(schema["required"]) == {
        "schema_version",
        "base_domain",
        "include_third_party",
        "scope_hosts",
        "exclude_hosts",
        "decisions",
    }
    assert set(decision_record["required"]) == {"url", "host", "selected", "reason", "matched_host"}
    assert set(reason_schema["enum"]) == {
        "base_domain",
        "scope_host",
        "include_third_party",
        "excluded_host",
        "out_of_scope_third_party",
    }


def test_jsonl_record_schemas_document_current_record_contracts() -> None:
    endpoint_schema = load_schema("endpoint-record.schema.json")
    secret_schema = load_schema("secret-finding-record.schema.json")

    assert set(endpoint_schema["required"]) == {"source", "type", "value", "normalized_value"}
    endpoint_type = endpoint_schema["properties"]["type"]
    assert set(endpoint_type["enum"]) == {"api_path", "ajax_call", "full_url"}

    assert set(secret_schema["required"]) == {
        "type",
        "pattern",
        "confidence",
        "label",
        "path",
        "line_number",
        "line_excerpt",
    }
    secret_type = secret_schema["properties"]["type"]
    assert secret_type["const"] == "secret"
