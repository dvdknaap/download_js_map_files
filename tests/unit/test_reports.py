from __future__ import annotations

from download_js_map_files.analysis.endpoints import EndpointFindings
from download_js_map_files.reports import ReportWriter


def test_report_writer_handles_empty_and_populated_reports(tmp_path) -> None:  # type: ignore[no-untyped-def]
    writer = ReportWriter(tmp_path)

    assert writer.append_suspicious_variables(["displayName"], "map.js") == []
    writer.write_url_list({"https://example.test/app.js"})
    writer.append_endpoint_findings("empty", EndpointFindings())
    writer.append_endpoint_findings(
        "populated",
        EndpointFindings(
            api_paths={"/api/test"},
            ajax_calls={"/v1/test"},
            full_urls={"https://example.test/api"},
            heuristic_rpc={'Keys found: name, method, endpoint\nCode Block (Line 1):\nname: "RpcName"'},
        ),
    )
    writer.write_aggregated_endpoints({"/api/test"}, {"RpcName"})

    assert "https://example.test/app.js" in (tmp_path / "urls.txt").read_text(encoding="utf-8")
    assert "/api/test" in (tmp_path / "discovered_endpoints.txt").read_text(encoding="utf-8")
    assert "https://example.test/api" in (tmp_path / "discovered_endpoints.txt").read_text(encoding="utf-8")
    writer.append_endpoint_export("populated", EndpointFindings(api_paths={"/api/test"}))
    writer.write_skipped_third_party({"https://cdn.example.test/app.js"})
    writer.write_summary({"status": "ok"})
    assert "/api/test" in (tmp_path / "endpoints.jsonl").read_text(encoding="utf-8")
    assert "cdn.example.test" in (tmp_path / "skipped_third_party_urls.txt").read_text(encoding="utf-8")
    assert '"status": "ok"' in (tmp_path / "summary.json").read_text(encoding="utf-8")
    assert "RpcName" in (tmp_path / "clean_rpc_endpoints.txt").read_text(encoding="utf-8")
