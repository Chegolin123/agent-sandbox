"""Журнал: цепочка хешей, обнаружение правки, удаления и мусора."""

from __future__ import annotations

import json
from pathlib import Path

from agentsandbox import audit


def _write(path: Path, count: int = 3) -> None:
    for number in range(count):
        audit.append(path, {"id": f"run-{number}", "exit_code": 0})


def test_append_builds_a_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    first = audit.append(path, {"id": "a"})
    second = audit.append(path, {"id": "b"})

    assert first["prev"] == audit.GENESIS
    assert second["prev"] == first["hash"]
    assert first["hash"] != second["hash"]
    assert audit.verify(path).ok


def test_missing_log_is_valid_and_empty(tmp_path: Path) -> None:
    result = audit.verify(tmp_path / "nothing.jsonl")
    assert result.ok
    assert result.entries == 0


def test_tampered_record_is_noticed(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path)

    lines = path.read_text(encoding="utf-8").splitlines()
    body = json.loads(lines[1])
    body["record"]["exit_code"] = 1
    lines[1] = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = audit.verify(path)
    assert not result.ok
    assert result.bad_line == 2
    assert "хеш" in result.reason


def test_deleted_line_breaks_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path)

    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = audit.verify(path)
    assert not result.ok
    assert result.bad_line == 2
    assert "разрыв" in result.reason


def test_garbage_line_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("{не json}\n", encoding="utf-8")

    result = audit.verify(path)
    assert not result.ok
    assert "битая" in result.reason
    assert result.bad_line == 1


def test_empty_lines_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path, count=1)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n")

    assert audit.verify(path).ok


def test_read_entries_returns_the_tail(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write(path, count=5)

    entries = audit.read_entries(path, limit=2)
    assert [entry["id"] for entry in entries] == ["run-3", "run-4"]
    assert len(audit.read_entries(path, limit=0)) == 5
    assert audit.read_entries(tmp_path / "nothing.jsonl") == []
