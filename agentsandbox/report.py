"""Человеческий вывод: одна карточка на прогон и строки журнала."""

from __future__ import annotations

import shlex
from typing import Any

from .runner import Outcome

STATE_LABELS = {
    "succeeded": "готово",
    "failed": "провал",
    "timeout": "таймаут",
    "cpu-limit": "лимит CPU",
    "memory-limit": "лимит памяти",
    "denied": "запрещено политикой",
    "error": "ошибка песочницы",
}


def program(command: list[str], limit: int = 70) -> str:
    text = shlex.join(command)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def format_outcome(outcome: Outcome) -> str:
    label = STATE_LABELS.get(outcome.state, outcome.state)
    lines = [
        f"запуск     {outcome.run_id}",
        f"команда    {program(outcome.command)}",
        f"состояние  {label}  (exit {outcome.exit_code})",
        f"время      {outcome.duration:.2f} с, процессор {outcome.cpu_time:.2f} с",
        f"память     {outcome.peak_memory_mb:.0f} МБ",
    ]
    if outcome.violations:
        lines.append("нарушено   " + "; ".join(outcome.violations))
    if outcome.state == "error" and outcome.detail:
        lines.append(f"детали     {outcome.detail}")
    lines.append(f"каталог    {outcome.run_dir}")
    lines.append(f"журнал     {outcome.audit_path}")
    return "\n".join(lines)


def format_entry(record: dict[str, Any], index: int | None = None) -> str:
    label = STATE_LABELS.get(str(record.get("state")), str(record.get("state")))
    head = (
        f"{record.get('ts', '?')}  {record.get('id', '?')}  "
        f"{label:<18} exit {record.get('exit_code')}"
    )
    body = f"    {program([str(item) for item in record.get('command', [])])}"
    stats = (
        f"    {float(record.get('duration_s') or 0):.2f} с, "
        f"cpu {float(record.get('cpu_s') or 0):.2f} с, "
        f"память {float(record.get('peak_memory_mb') or 0):.0f} МБ"
    )
    lines = [head, body, stats]
    violations = record.get("violations") or []
    if violations:
        lines.append("    нарушено: " + "; ".join(str(item) for item in violations))
    return "\n".join(lines)
