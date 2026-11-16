"""Исполнители: Windows Job Objects и POSIX rlimit.

Общий контракт один: запустить команду в каталоге с окружением, уложиться в лимиты
и вернуть факты — код возврата, время, процессорное время, пик памяти, причину остановки.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(slots=True)
class Execution:
    exit_code: int
    duration: float
    cpu_time: float
    peak_memory_mb: float
    reason: str  # exit | timeout | cpu | memory
    processes: int = 0
    detail: str = ""

    @property
    def succeeded(self) -> bool:
        return self.reason == "exit" and self.exit_code == 0


def get_backend():
    if os.name == "nt":
        from .windows_job import WindowsJobBackend

        return WindowsJobBackend()
    from .posix_rlimit import PosixRlimitBackend

    return PosixRlimitBackend()
