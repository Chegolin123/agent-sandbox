"""Лимиты и политика запуска: всё, что можно задать до старта чужого кода."""

from __future__ import annotations

import hashlib
import sys
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """Политика или лимиты противоречат друг другу."""


DEFAULT_TIMEOUT = 30.0
DEFAULT_CPU = 20.0
DEFAULT_MEMORY_MB = 1024
DEFAULT_PROCS = 16


@dataclass(frozen=True, slots=True)
class Limits:
    """Жёсткие лимиты одного запуска.

    timeout     — стенных секунд до принудительного убийства дерева процессов;
    cpu         — секунд процессорного времени (сумма по всем процессам);
    memory_mb   — предел памяти на задачу;
    procs       — сколько процессов может жить одновременно (только Windows).
    """

    timeout: float = DEFAULT_TIMEOUT
    cpu: float = DEFAULT_CPU
    memory_mb: int = DEFAULT_MEMORY_MB
    procs: int = DEFAULT_PROCS

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ConfigError("timeout должен быть больше нуля")
        if self.cpu <= 0:
            raise ConfigError("cpu должен быть больше нуля")
        if self.memory_mb < 16:
            raise ConfigError("memory_mb меньше 16 МБ не имеет смысла")
        if self.procs < 1:
            raise ConfigError("procs должен быть не меньше 1")

    def as_dict(self) -> dict[str, Any]:
        return {
            "timeout": self.timeout,
            "cpu": self.cpu,
            "memory_mb": self.memory_mb,
            "procs": self.procs,
        }


DEFAULT_ALLOW = ("python", "python3", "node", "bash", "sh", "pwsh", "powershell", "cmd")

DEFAULT_ENV_KEEP = ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "LANG", "LC_ALL", "TERM")


@dataclass(slots=True)
class Policy:
    limits: Limits = field(default_factory=Limits)
    allow_programs: tuple[str, ...] = DEFAULT_ALLOW
    env_keep: tuple[str, ...] = DEFAULT_ENV_KEEP
    audit_path: Path = Path("audit/audit.jsonl")
    runs_dir: Path = Path("runs")
    source: Path | None = None

    @property
    def audit_digest(self) -> str:
        """Хеш политики: попадает в журнал, чтобы прогон нельзя было переписать задним числом."""
        body = "\n".join(
            [
                f"timeout={self.limits.timeout:g}",
                f"cpu={self.limits.cpu:g}",
                f"memory_mb={self.limits.memory_mb}",
                f"procs={self.limits.procs}",
                "allow=" + ",".join(self.allow_programs),
                "env=" + ",".join(self.env_keep),
            ]
        )
        return hashlib.sha256(body.encode()).hexdigest()

    def program_allowed(self, program: str) -> bool:
        """Пустой список означает «разрешено всё» — это осознанный компромисс, см. README."""
        if not self.allow_programs:
            return True
        # Путь может прийти в виндовом виде даже на Linux, поэтому режем оба разделителя.
        name = program.replace("\\", "/").rsplit("/", 1)[-1].lower()
        # .exe срезаем на любой платформе: политику часто пишут на Windows,
        # а читают в CI на Linux, и расхождение из-за суффикса — лишний сюрприз.
        if name.endswith(".exe"):
            name = name[:-4]
        return name in {item.lower().removesuffix(".exe") for item in self.allow_programs}

    def with_overrides(self, **overrides: Any) -> Policy:
        limits_fields = {"timeout", "cpu", "memory_mb", "procs"}
        next_limits = self.limits
        policy_fields: dict[str, Any] = {}
        for key, value in overrides.items():
            if value is None:
                continue
            if key in limits_fields:
                next_limits = replace(next_limits, **{key: value})
            else:
                policy_fields[key] = value
        policy = replace(self, limits=next_limits, **policy_fields)
        return policy


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        # utf-8-sig: блокнот и PowerShell любят дописать BOM, а TOML его не терпит.
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError as exc:  # pragma: no cover — сообщение важнее покрытия
        raise ConfigError(f"нет файла политики: {path}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{path}: файл не в UTF-8 — {exc}") from exc
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: некорректный TOML — {exc}") from exc


def load_policy(path: str | Path | None = None) -> Policy:
    """Читает TOML рядом с политикой; всё относительное считается от её каталога."""
    if path is None:
        return Policy()

    source = Path(path).expanduser().resolve()
    raw = _read_toml(source)
    base = source.parent

    limits_raw = raw.get("limits", {})
    limits = Limits(
        timeout=float(limits_raw.get("timeout", DEFAULT_TIMEOUT)),
        cpu=float(limits_raw.get("cpu", DEFAULT_CPU)),
        memory_mb=int(limits_raw.get("memory_mb", DEFAULT_MEMORY_MB)),
        procs=int(limits_raw.get("procs", DEFAULT_PROCS)),
    )

    policy_raw = raw.get("policy", {})
    allow = policy_raw.get("allow_programs", DEFAULT_ALLOW)
    env_keep = policy_raw.get("env_keep", DEFAULT_ENV_KEEP)
    paths_raw = raw.get("paths", {})

    audit_path = (base / paths_raw.get("audit", "audit/audit.jsonl")).resolve()
    runs_dir = (base / paths_raw.get("runs", "runs")).resolve()

    return Policy(
        limits=limits,
        allow_programs=tuple(str(item) for item in allow),
        env_keep=tuple(str(item) for item in env_keep),
        audit_path=audit_path,
        runs_dir=runs_dir,
        source=source,
    )


def host_info() -> dict[str, str]:
    import platform

    return {
        "os": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "backend": "windows-job" if sys.platform == "win32" else "posix-rlimit",
    }
