from __future__ import annotations

from download_js_map_files.analysis.endpoints import EndpointExtractor


def test_extracts_standard_endpoints_and_rpc_names() -> None:
    content = """
    fetch("/api/users");
    axios.get("/v1/accounts");
    const full = "https://api.example.test/v2/items";
    const rpc = {
      name: "CreateUser",
      params: ["email"],
      endpoint: "/svc/create",
      method: "POST",
      options: {}
    };
    """

    findings = EndpointExtractor.extract(content)
    rpc_names = set().union(*(EndpointExtractor.extract_rpc_names(block) for block in findings.heuristic_rpc))

    assert "/api/users" in findings.api_paths
    assert "/v1/accounts" in findings.ajax_calls
    assert "https://api.example.test/v2/items" in findings.full_urls
    assert "/svc/create" in findings.api_paths
    assert "CreateUser" in rpc_names
    assert findings.has_findings is True
    assert "/api/users" in findings.standard_endpoints


def test_rpc_name_filter_removes_common_noise() -> None:
    assert EndpointExtractor.extract_rpc_names('method: "GET" action: "RealAction"') == {"RealAction"}


def test_long_minified_lines_are_skipped_by_proximity_scan() -> None:
    content = "name method endpoint " + ("x" * 1200)

    assert not EndpointExtractor.extract(content).heuristic_rpc
