"""Windows: Job Object с лимитами памяти, процессорного времени и числа процессов.

Главная тонкость — гонка на старте. Если создать процесс обычным `subprocess` и
прицепить его к job-объекту после, он успевает наплодить детей, которые в job уже не
попадут. Поэтому процесс создаётся приостановленным (`CREATE_SUSPENDED`), сначала
прицепляется к job, и только потом получает поток управления через `NtResumeProcess`.
Отдельного `CreateProcessW` здесь нет намеренно: перекладывать окружение и хендлы на
ctypes оказалось дороже, чем доверить это `subprocess`.
"""

from __future__ import annotations

import ctypes
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

from . import Execution

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

DWORD = wintypes.DWORD
HANDLE = wintypes.HANDLE
BOOL = wintypes.BOOL

JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9

JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

CREATE_SUSPENDED = 0x00000004
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000

EXIT_TIMEOUT = 124
EXIT_CPU = 152

WAIT_OBJECT_0 = 0x00000000
INFINITE = 0xFFFFFFFF
WATCHDOG_INTERVAL_MS = 50


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", DWORD),
        ("SchedulingClass", DWORD),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_int64),
        ("TotalKernelTime", ctypes.c_int64),
        ("ThisPeriodTotalUserTime", ctypes.c_int64),
        ("ThisPeriodTotalKernelTime", ctypes.c_int64),
        ("TotalPageFaultCount", DWORD),
        ("TotalProcesses", DWORD),
        ("ActiveProcesses", DWORD),
        ("TotalTerminatedProcesses", DWORD),
    ]


kernel32.CreateJobObjectW.restype = HANDLE
kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]

kernel32.SetInformationJobObject.restype = BOOL
kernel32.SetInformationJobObject.argtypes = [HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD]

kernel32.QueryInformationJobObject.restype = BOOL
kernel32.QueryInformationJobObject.argtypes = [
    HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD, ctypes.c_void_p,
]

kernel32.AssignProcessToJobObject.restype = BOOL
kernel32.AssignProcessToJobObject.argtypes = [HANDLE, HANDLE]

kernel32.TerminateJobObject.restype = BOOL
kernel32.TerminateJobObject.argtypes = [HANDLE, wintypes.UINT]

kernel32.CloseHandle.restype = BOOL
kernel32.CloseHandle.argtypes = [HANDLE]

kernel32.WaitForSingleObject.restype = DWORD
kernel32.WaitForSingleObject.argtypes = [HANDLE, DWORD]

ntdll.NtResumeProcess.restype = ctypes.c_long
ntdll.NtResumeProcess.argtypes = [HANDLE]


def _fail(what: str) -> OSError:
    code = ctypes.get_last_error()
    return OSError(code, f"{what}: {ctypes.FormatError(code)}")


class WindowsJobBackend:
    """Лимиты держит job-объект; процессорное время дополнительно добивает сторож."""

    name = "windows-job"

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
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            raise _fail("CreateJobObjectW")

        try:
            self._apply_limits(job, cpu, memory_mb, procs)
            return self._run(
                job, argv, cwd, env, timeout, cpu, memory_mb,
                stdout_path, stderr_path, on_start,
            )
        finally:
            # KILL_ON_JOB_CLOSE: закрытие хендла добивает всё, что осталось в job.
            kernel32.CloseHandle(HANDLE(job))

    @staticmethod
    def _apply_limits(job: int, cpu: float, memory_mb: int, procs: int) -> None:
        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_JOB_TIME
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        info.BasicLimitInformation.PerJobUserTimeLimit = int(cpu * 10_000_000)  # 100 нс
        info.BasicLimitInformation.ActiveProcessLimit = procs
        limit_bytes = memory_mb * 1024 * 1024
        info.ProcessMemoryLimit = limit_bytes
        info.JobMemoryLimit = limit_bytes

        if not kernel32.SetInformationJobObject(
            HANDLE(job),
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            raise _fail("SetInformationJobObject")

    def _run(
        self,
        job: int,
        argv: list[str],
        cwd: Path,
        env: dict[str, str],
        timeout: float,
        cpu: float,
        memory_mb: int,
        stdout_path: Path,
        stderr_path: Path,
        on_start=None,
    ) -> Execution:
        started = time.monotonic()
        with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
            proc = subprocess.Popen(
                argv,
                cwd=str(cwd),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                close_fds=True,
                creationflags=CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
            )

            process_handle = HANDLE(proc._handle)  # noqa: SLF001 — другого способа нет
            if not kernel32.AssignProcessToJobObject(HANDLE(job), process_handle):
                proc.kill()
                proc.wait()
                raise _fail("AssignProcessToJobObject")

            status = ntdll.NtResumeProcess(process_handle)
            if status != 0:
                proc.kill()
                proc.wait()
                raise OSError(f"NtResumeProcess: NTSTATUS {status:#010x}")

            if on_start is not None:
                on_start()

            # Ядро проверяет PerJobUserTimeLimit с задержкой в несколько секунд —
            # для песочницы это слишком много. Поэтому сторож опрашивает учёт сам,
            # а job-лимит остаётся страховкой на случай, если сторож не успел.
            timed_out = False
            cpu_exceeded = False
            deadline = started + timeout
            while True:
                signalled = kernel32.WaitForSingleObject(process_handle, WATCHDOG_INTERVAL_MS)
                if signalled == WAIT_OBJECT_0:
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    kernel32.TerminateJobObject(HANDLE(job), EXIT_TIMEOUT)
                    kernel32.WaitForSingleObject(process_handle, INFINITE)
                    break
                if self._accounting(job)[0] >= cpu:
                    cpu_exceeded = True
                    kernel32.TerminateJobObject(HANDLE(job), EXIT_CPU)
                    kernel32.WaitForSingleObject(process_handle, INFINITE)
                    break
            proc.wait()

        duration = time.monotonic() - started
        exit_code = proc.returncode if proc.returncode is not None else EXIT_TIMEOUT
        cpu_time, peak_mb, processes = self._accounting(job)

        reason = "exit"
        if timed_out:
            reason = "timeout"
        elif cpu_exceeded:
            reason = "cpu"
        elif exit_code != 0 and peak_mb >= memory_mb * 0.9:
            reason = "memory"

        return Execution(
            exit_code=int(exit_code),
            duration=round(duration, 3),
            cpu_time=round(cpu_time, 3),
            peak_memory_mb=round(peak_mb, 1),
            reason=reason,
            processes=processes,
        )

    @staticmethod
    def _accounting(job: int) -> tuple[float, float, int]:
        accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
        kernel32.QueryInformationJobObject(
            HANDLE(job),
            JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
            ctypes.byref(accounting),
            ctypes.sizeof(accounting),
            None,
        )
        extended = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        kernel32.QueryInformationJobObject(
            HANDLE(job),
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(extended),
            ctypes.sizeof(extended),
            None,
        )
        cpu_time = (accounting.TotalUserTime + accounting.TotalKernelTime) / 10_000_000
        peak_mb = extended.PeakJobMemoryUsed / (1024 * 1024)
        return cpu_time, peak_mb, int(accounting.TotalProcesses)


def probe() -> dict[str, object]:
    """Что реально умеет эта машина: проверяем job-объект, а не верим документации."""
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return {
            "backend": "windows-job",
            "available": False,
            "error": ctypes.FormatError(ctypes.get_last_error()),
        }
    kernel32.CloseHandle(HANDLE(job))
    return {
        "backend": "windows-job",
        "available": True,
        "wall_time": True,
        "cpu_time": True,
        "memory": True,
        "processes": True,
        "kill_tree": True,
        "filesystem_isolation": False,
        "network_isolation": False,
    }
