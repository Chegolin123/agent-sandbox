"""Журнал прогонов: JSONL с цепочкой хешей.

Каждая строка содержит `prev` — хеш предыдущей записи. Правка любой строки ломает
цепочку, а вставка или удаление строки видны по разрыву. Это не защита от того, кто
может переписать весь файл, но честный способ заметить выборочную правку.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


class AuditError(RuntimeError):
    """С журналом что-то не так."""


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def entry_hash(record: dict[str, Any], prev: str) -> str:
    return hashlib.sha256(_canonical({"record": record, "prev": prev})).hexdigest()


def _last_hash(path: Path) -> str:
    if not path.exists() or path.stat().st_size == 0:
        return GENESIS
    with path.open("rb") as handle:
        handle.seek(0, 2)
        size = handle.tell()
        chunk = min(size, 1_000_000)
        handle.seek(size - chunk)
        tail = handle.read().decode("utf-8", errors="replace").splitlines()
    for line in reversed(tail):
        if line.strip():
            try:
                return json.loads(line)["hash"]
            except (json.JSONDecodeError, KeyError) as exc:
                raise AuditError("последняя запись журнала повреждена") from exc
    return GENESIS


def append(path: str | Path, record: dict[str, Any]) -> dict[str, Any]:
    """Дописывает запись и возвращает её вместе с цепочкой."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    prev = _last_hash(target)
    body = {"record": record, "prev": prev, "hash": entry_hash(record, prev)}
    line = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    with target.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(line + "\n")
        handle.flush()
    return body


@dataclass(slots=True)
class VerifyResult:
    ok: bool
    entries: int
    reason: str = ""
    bad_line: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "entries": self.entries,
            "reason": self.reason,
            "bad_line": self.bad_line,
        }


def verify(path: str | Path) -> VerifyResult:
    target = Path(path)
    if not target.exists():
        return VerifyResult(ok=True, entries=0, reason="журнала ещё нет")

    prev = GENESIS
    count = 0
    with target.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                body = json.loads(line)
                record = body["record"]
                claimed = body["hash"]
                claimed_prev = body["prev"]
            except (json.JSONDecodeError, KeyError, TypeError):
                return VerifyResult(ok=False, entries=count, reason="битая строка", bad_line=number)
            if claimed_prev != prev:
                return VerifyResult(
                    ok=False, entries=count, reason="разрыв цепочки: запись правили или удаляли",
                    bad_line=number,
                )
            if entry_hash(record, prev) != claimed:
                return VerifyResult(
                    ok=False, entries=count, reason="хеш не совпадает", bad_line=number
                )
            prev = claimed
            count += 1

    return VerifyResult(ok=True, entries=count)


def read_entries(path: str | Path, limit: int = 20) -> list[dict[str, Any]]:
    target = Path(path)
    if not target.exists():
        return []
    entries: list[dict[str, Any]] = []
    with target.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                entries.append(json.loads(line)["record"])
    return entries[-limit:] if limit else entries
