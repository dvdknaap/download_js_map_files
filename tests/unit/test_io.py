from __future__ import annotations

from download_js_map_files.io import append_text, unique_filename, write_text


def test_write_append_and_unique_filename(tmp_path) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "nested" / "bad_name.js"
    write_text(target, "one")
    append_text(target, "\ntwo")

    assert target.read_text(encoding="utf-8") == "one\ntwo"
    assert unique_filename(target.parent, "bad name.js") == "bad_name_1.js"
    assert unique_filename(target.parent, "???") == "script.js"
