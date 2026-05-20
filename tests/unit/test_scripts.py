from __future__ import annotations

from download_js_map_files.analysis.scripts import extract_script_references


def test_extract_script_references_finds_dynamic_loader_paths() -> None:
    content = """
    const script = document.createElement("script");
    script.src = "/assets/app.js?v=1";
    import("./chunks/dashboard.mjs");
    const ignoredMap = "app.js.map";
    const ignoredData = "data:text/javascript,console.log(1)";
    """

    assert extract_script_references(content) == {"/assets/app.js?v=1", "./chunks/dashboard.mjs"}
