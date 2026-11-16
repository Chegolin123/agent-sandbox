"""Окружение для чужого скрипта: минимум переменных и ни одного секрета.

Идея простая: дочерний процесс получает только то, что нужно интерпретатору,
плюс явно разрешённое политикой. Всё, что похоже на токен или ключ, вырезается —
даже если политика просит оставить переменную целиком.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

SECRET_MARKERS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "APIKEY",
    "API_KEY",
    "CREDENTIAL",
    "PRIVATE_KEY",
    "COOKIE",
    "SESSION_ID",
    "SESSION_TOKEN",
    "SESSION_KEY",
    "AUTH_TOKEN",
    "AUTHORIZATION",
    "BEARER",
)

# Известные имена, которые вырезаем, даже если маркер случайно не сработал.
DENY_EXACT = frozenset(
    {
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GITLAB_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "HF_TOKEN",
        "HUGGING_FACE_HUB_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "SSH_AUTH_SOCK",
        "KUBECONFIG",
        "DOCKER_CONFIG",
        "NPM_TOKEN",
        "PYPI_TOKEN",
    }
)

# Значения этих переменных дочернему процессу нужны, чтобы вообще запуститься.
BASE_KEEP = {
    "nt": ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP", "USERPROFILE"),
    "posix": ("PATH", "LANG", "LC_ALL", "TERM"),
}


@dataclass(slots=True)
class PreparedEnv:
    values: dict[str, str]
    dropped: list[str] = field(default_factory=list)
    kept_extra: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, str]:
        return dict(self.values)


def is_secret(name: str) -> bool:
    upper = name.upper()
    if upper in DENY_EXACT:
        return True
    return any(marker in upper for marker in SECRET_MARKERS)


def prepare(
    environ: dict[str, str],
    keep: tuple[str, ...] = (),
    temp_dir: str | None = None,
) -> PreparedEnv:
    """Собирает окружение: базовые переменные + явно разрешённые, без секретов."""
    base_names = BASE_KEEP["nt" if os.name == "nt" else "posix"]
    wanted = list(dict.fromkeys([*base_names, *keep]))
    wanted_upper = {name.upper() for name in wanted}

    result: dict[str, str] = {}
    dropped: list[str] = []
    kept_extra: list[str] = []

    base_upper = {item.upper() for item in base_names}

    for name, value in environ.items():
        upper = name.upper()
        # Секрет вырезаем всегда, даже если политика просила его оставить,
        # и всегда показываем в отчёте — иначе непонятно, почему скрипт его не видит.
        if is_secret(name) and upper not in base_upper:
            dropped.append(name)
            continue
        if upper not in wanted_upper:
            continue
        result[name] = value
        if upper not in base_upper:
            kept_extra.append(name)

    if temp_dir:
        for key in ("TEMP", "TMP", "TMPDIR"):
            result[key] = temp_dir

    # Дочерний процесс не должен подхватывать пользовательские пакеты и .pth-файлы.
    result["PYTHONNOUSERSITE"] = "1"
    result["PYTHONUNBUFFERED"] = "1"
    result["PYTHONDONTWRITEBYTECODE"] = "1"

    if os.name == "posix":
        result.setdefault("HOME", temp_dir or "/tmp")

    return PreparedEnv(
        values=result,
        dropped=sorted(set(dropped)),
        kept_extra=sorted(set(kept_extra)),
    )
