"""POSIX: rlimit на процессорное время, память и размер файлов, плюс своя сессия.

`setsid` нужен, чтобы таймаут убивал всю группу процессов одной командой, а не только
первый процесс. Дочерние процессы при этом получают те же rlimit по наследству.
"""

from __future__ import annotations

import os
import resource
import signal
import subprocess
import sys
import time
from pathlib import Path

from . import Execution

EXIT_TIMEOUT = 124
EXIT_CPU = 152


def _apply_limits(cpu: float, memory_mb: int) -> None:
    cpu_seconds = max(1, int(round(cpu)))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))

    address_space = memory_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (address_space, address_space))

    # Дампы памяти после падения нам не нужны: это гигабайты в рабочем каталоге.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    os.setsid()


class PosixRlimitBackend:
    name = "posix-rlimit"

    def probe(self) -> dict[str, object]:
        return probe()

    def run(
        self,
        argv: list[str],
        cwd: Path,
        env: dict[str, str],
        *,
        timeout: float,
        cpu: float,
        memory_mb: int,
        procs: int,
        stdout_path: Path,
        stderr_path: Path,
        on_start=None,
    ) -> Execution:
        started = time.monotonic()
        with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
            proc = subprocess.Popen(
                argv,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                close_fds=True,
                preexec_fn=lambda: _apply_limits(cpu, memory_mb),
            )
            if on_start is not None:
                on_start()

            deadline = started + timeout
            timed_out = False
            while True:
                pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
                if pid == proc.pid:
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    self._kill_group(proc.pid)
                    pid, status, usage = os.wait4(proc.pid, 0)
                    break
                time.sleep(0.02)

        proc.returncode = os.waitstatus_to_exitcode(status)

        duration = time.monotonic() - started
        cpu_time = usage.ru_utime + usage.ru_stime
        if sys.platform.startswith("linux"):
            peak_mb = usage.ru_maxrss / 1024  # Linux отдаёт килобайты
        else:
            peak_mb = usage.ru_maxrss / 1024**2  # macOS отдаёт байты

        reason = "exit"
        if timed_out:
            reason = "timeout"
        elif proc.returncode == -signal.SIGXCPU or (
            proc.returncode == -signal.SIGKILL and cpu_time >= cpu * 0.9
        ):
            reason = "cpu"
        elif proc.returncode != 0 and peak_mb >= memory_mb * 0.9:
            reason = "memory"

        return Execution(
            exit_code=proc.returncode,
            duration=round(duration, 3),
            cpu_time=round(cpu_time, 3),
            peak_memory_mb=round(peak_mb, 1),
            reason=reason,
            processes=0,
        )

    @staticmethod
    def _kill_group(pid: int) -> None:
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except PermissionError:  # pragma: no cover — своя же группа, но всякое бывает
            os.kill(pid, signal.SIGKILL)


def probe() -> dict[str, object]:
    """rlimit есть всегда, а вот лимит числа процессов без cgroups не сделать."""
    return {
        "backend": "posix-rlimit",
        "available": True,
        "wall_time": True,
        "cpu_time": True,
        "memory": True,
        "processes": False,
        "kill_tree": True,
        "filesystem_isolation": False,
        "network_isolation": False,
    }