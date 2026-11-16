"""Оркестровка: политика → окружение → лимиты → запуск → журнал."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__, audit
from . import env as env_module
from .backends import get_backend
from .config import Limits, Policy, host_info

EXIT_DENIED = 126
EXIT_NOT_FOUND = 127
EXIT_SANDBOX = 125

LIMIT_CODES = {
    "timeout": 124,
    "cpu-limit": 152,
    "memory-limit": 137,
}


@dataclass(slots=True)
class RunRequest:
    argv: list[str]
    policy: Policy
    cwd: Path | None = None
    echo: bool = True
    label: str | None = None


@dataclass(slots=True)
class Outcome:
    run_id: str
    state: str
    exit_code: int
    duration: float
    cpu_time: float
    peak_memory_mb: float
    run_dir: Path
    stdout_path: Path
    stderr_path: Path
    command: list[str]
    audit_path: Path
    violations: list[str] = field(default_factory=list)
    detail: str = ""
    record: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.state == "succeeded"

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "state": self.state,
            "exit_code": self.exit_code,
            "duration": self.duration,
            "cpu_time": self.cpu_time,
            "peak_memory_mb": self.peak_memory_mb,
            "run_dir": str(self.run_dir),
            "stdout": str(self.stdout_path),
            "stderr": str(self.stderr_path),
            "command": self.command,
            "violations": self.violations,
            "detail": self.detail,
        }


def _file_digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
                size += len(chunk)
    except FileNotFoundError:
        return "", 0
    return digest.hexdigest(), size


class _Echo(threading.Thread):
    """Показывает вывод задачи по мере появления: файлы читаются, байты не теряются."""

    def __init__(self, stdout_path: Path, stderr_path: Path):
        super().__init__(daemon=True)
        self.stdout_path = stdout_path
        self.stderr_path = stderr_path
        self.stop_event = threading.Event()

    def run(self) -> None:
        handles = [self.stdout_path.open("rb"), self.stderr_path.open("rb")]
        targets = [
            getattr(sys.stdout, "buffer", sys.stdout),
            getattr(sys.stderr, "buffer", sys.stderr),
        ]
        try:
            while True:
                wrote = False
                for index, handle in enumerate(handles):
                    chunk = handle.read(8192)
                    if chunk:
                        targets[index].write(chunk)
                        targets[index].flush()
                        wrote = True
                if self.stop_event.is_set() and not wrote:
                    break
                if not wrote:
                    self.stop_event.wait(0.1)
        finally:
            for handle in handles:
                handle.close()

    def stop(self) -> None:
        self.stop_event.set()
        if self.ident is not None:  # поток мог не успеть стартовать, если запуск упал сразу
            self.join(timeout=5)


def _new_run_id() -> str:
    return f"{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:6]}"


MEMORY_REFUSAL_MARKERS = (
    "memoryerror",
    "std::bad_alloc",
    "bad_alloc",
    "bad allocation",
    "cannot allocate memory",
    "not enough memory",
    "out of memory",
)


def _memory_refused(stderr_path: Path) -> bool:
    """Процесс мог упасть не от убийства, а от отказа в памяти.

    Job-объект Windows не убивает за превышение памяти: он отказывает в выделении,
    и интерпретатор падает сам (`MemoryError`, `bad_alloc`). Формально это тот же
    лимит, но приходит он изнутри процесса, поэтому ловим по тексту ошибки.
    """
    try:
        with stderr_path.open("rb") as handle:
            handle.seek(0, 2)
            handle.seek(max(0, handle.tell() - 8192))
            tail = handle.read().decode("utf-8", errors="replace").lower()
    except OSError:
        return False
    return any(marker in tail for marker in MEMORY_REFUSAL_MARKERS)


def _limit_violations(limits: Limits, state: str) -> list[str]:
    if state == "timeout":
        return [f"стенное время больше {limits.timeout:g} с"]
    if state == "cpu-limit":
        return [f"процессорное время больше {limits.cpu:g} с"]
    if state == "memory-limit":
        return [f"память больше {limits.memory_mb} МБ"]
    return []


def run(request: RunRequest, backend: Any | None = None) -> Outcome:
    policy = request.policy
    limits = policy.limits
    backend = backend or get_backend()

    run_id = _new_run_id()
    run_dir = policy.runs_dir / run_id
    stdout_path = run_dir / "stdout.log"
    stderr_path = run_dir / "stderr.log"
    workspace = (request.cwd or run_dir / "work").resolve()
    temp_dir = run_dir / "tmp"

    for directory in (run_dir, workspace, temp_dir):
        directory.mkdir(parents=True, exist_ok=True)

    # Файлы вывода существуют с самого начала: прогон, отклонённый политикой,
    # тоже должен оставить после себя целый каталог, а не половину.
    for log_path in (stdout_path, stderr_path):
        log_path.touch()

    base_record: dict[str, Any] = {
        "id": run_id,
        "label": request.label,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "command": request.argv,
        "workspace": str(workspace),
        "limits": limits.as_dict(),
        "policy": {
            "source": str(policy.source) if policy.source else None,
            "sha256": policy.audit_digest,
        },
        "host": host_info(),
        "sandbox": __version__,
    }

    program = request.argv[0] if request.argv else ""
    if not policy.program_allowed(program):
        return _finish(
            run_id=run_id,
            run_dir=run_dir,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            command=request.argv,
            base_record=base_record,
            state="denied",
            exit_code=EXIT_DENIED,
            duration=0.0,
            cpu_time=0.0,
            peak_memory_mb=0.0,
            violations=[f"программа {program} не разрешена политикой"],
            detail="policy: allow_programs",
            policy=policy,
        )

    prepared = env_module.prepare(dict(os.environ), policy.env_keep, str(temp_dir))
    resolved = shutil.which(program, path=prepared.values.get("PATH"))
    if resolved is None:
        return _finish(
            run_id=run_id,
            run_dir=run_dir,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            command=request.argv,
            base_record=base_record,
            state="error",
            exit_code=EXIT_NOT_FOUND,
            duration=0.0,
            cpu_time=0.0,
            peak_memory_mb=0.0,
            violations=[f"программа не найдена: {program}"],
            detail="shutil.which",
            policy=policy,
        )

    argv = [resolved, *request.argv[1:]]

    echo = _Echo(stdout_path, stderr_path) if request.echo else None
    started = time.monotonic()
    try:
        execution = backend.run(
            argv,
            workspace,
            prepared.values,
            timeout=limits.timeout,
            cpu=limits.cpu,
            memory_mb=limits.memory_mb,
            procs=limits.procs,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            on_start=echo.start if echo else None,
        )
    except OSError as exc:
        return _finish(
            run_id=run_id,
            run_dir=run_dir,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            command=request.argv,
            base_record=base_record,
            state="error",
            exit_code=EXIT_SANDBOX,
            duration=round(time.monotonic() - started, 3),
            cpu_time=0.0,
            peak_memory_mb=0.0,
            violations=[f"песочница не смогла запустить: {exc}"],
            detail=str(exc),
            policy=policy,
        )
    finally:
        if echo is not None:
            echo.stop()

    state = {
        "exit": "succeeded" if execution.exit_code == 0 else "failed",
        "timeout": "timeout",
        "cpu": "cpu-limit",
        "memory": "memory-limit",
    }.get(execution.reason, "failed")

    if state == "failed" and _memory_refused(stderr_path):
        state = "memory-limit"

    exit_code = LIMIT_CODES.get(state, _normalise(execution.exit_code))

    return _finish(
        run_id=run_id,
        run_dir=run_dir,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        command=request.argv,
        base_record=base_record,
        state=state,
        exit_code=exit_code,
        duration=execution.duration,
        cpu_time=execution.cpu_time,
        peak_memory_mb=execution.peak_memory_mb,
        violations=_limit_violations(limits, state),
        detail=execution.detail,
        policy=policy,
        raw_exit_code=execution.exit_code,
        processes=execution.processes,
        env_info={"dropped": prepared.dropped, "kept": prepared.kept_extra},
    )


def _normalise(code: int) -> int:
    """Приводит код возврата к тому, что умеет оболочка: 0..255."""
    if code < 0:
        return min(255, 128 + abs(code))
    return 0 if code == 0 else min(255, code)


def _finish(
    *,
    run_id: str,
    run_dir: Path,
    stdout_path: Path,
    stderr_path: Path,
    command: list[str],
    base_record: dict[str, Any],
    state: str,
    exit_code: int,
    duration: float,
    cpu_time: float,
    peak_memory_mb: float,
    violations: list[str],
    detail: str,
    policy: Policy,
    raw_exit_code: int | None = None,
    processes: int = 0,
    env_info: dict[str, Any] | None = None,
) -> Outcome:
    stdout_hash, stdout_size = _file_digest(stdout_path)
    stderr_hash, stderr_size = _file_digest(stderr_path)

    record = dict(base_record)
    record.update(
        {
            "state": state,
            "exit_code": exit_code,
            "raw_exit_code": raw_exit_code if raw_exit_code is not None else exit_code,
            "duration_s": duration,
            "cpu_s": cpu_time,
            "peak_memory_mb": peak_memory_mb,
            "processes": processes,
            "violations": violations,
            "detail": detail,
            "stdout": {"path": str(stdout_path), "bytes": stdout_size, "sha256": stdout_hash},
            "stderr": {"path": str(stderr_path), "bytes": stderr_size, "sha256": stderr_hash},
            "env": env_info or {},
        }
    )

    (run_dir / "meta.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    audit.append(policy.audit_path, record)

    return Outcome(
        run_id=run_id,
        state=state,
        exit_code=exit_code,
        duration=duration,
        cpu_time=cpu_time,
        peak_memory_mb=peak_memory_mb,
        run_dir=run_dir,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        command=command,
        audit_path=policy.audit_path,
        violations=violations,
        detail=detail,
        record=record,
    )
