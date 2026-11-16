"""Прогоны целиком: успех, провал, таймаут, лимиты, отказ политики."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agentsandbox import audit
from agentsandbox.config import Limits, Policy
from agentsandbox.runner import RunRequest, run


def _run(policy: Policy, argv: list[str], **limits) -> object:
    if limits:
        policy = policy.with_overrides(**limits)
    return run(RunRequest(argv=argv, policy=policy, echo=False))


def test_successful_run(policy: Policy, python: str) -> None:
    outcome = _run(policy, [python, "-c", "print('hello')"])

    assert outcome.ok
    assert outcome.state == "succeeded"
    assert outcome.exit_code == 0
    assert "hello" in outcome.stdout_path.read_text(encoding="utf-8")
    assert outcome.stdout_path.exists()

    record = json.loads((outcome.run_dir / "meta.json").read_text(encoding="utf-8"))
    assert record["state"] == "succeeded"
    assert record["stdout"]["bytes"] > 0
    assert record["stdout"]["sha256"] == outcome.record["stdout"]["sha256"]
    assert record["policy"]["sha256"] == policy.audit_digest

    assert audit.verify(policy.audit_path).ok


def test_failed_exit_code_is_preserved(policy: Policy, python: str) -> None:
    outcome = _run(policy, [python, "-c", "raise SystemExit(3)"])

    assert not outcome.ok
    assert outcome.state == "failed"
    assert outcome.exit_code == 3


def test_program_not_found(policy: Policy) -> None:
    outcome = _run(policy, ["definitely-no-such-program-xyz"])

    assert outcome.state == "error"
    assert outcome.exit_code == 127
    assert "не найдена" in outcome.violations[0]


def test_policy_denies_program(policy_factory, python: str) -> None:
    policy = policy_factory(allow_programs=("only-this-one",))

    outcome = _run(policy, [python, "-c", "print('must not run')"])

    assert outcome.state == "denied"
    assert outcome.exit_code == 126
    assert "не разрешена" in outcome.violations[0]
    assert not outcome.stdout_path.read_text(encoding="utf-8")


def test_wall_timeout(policy: Policy, python: str) -> None:
    outcome = _run(policy, [python, "-c", "import time; time.sleep(60)"], timeout=1.5)

    assert outcome.state == "timeout"
    assert outcome.exit_code == 124
    assert outcome.duration < 15
    assert "стенное время" in outcome.violations[0]


def test_cpu_limit(policy: Policy, python: str) -> None:
    outcome = _run(policy, [python, "-c", "x = 0\nwhile True:\n    x += 1"], cpu=1, timeout=60)

    assert outcome.state == "cpu-limit"
    assert outcome.exit_code == 152
    assert outcome.cpu_time >= 0.9


@pytest.mark.skipif(os.name != "nt", reason="мягкий лимит памяти проверяется на Windows")
def test_memory_limit_on_windows(policy: Policy, python: str) -> None:
    outcome = _run(
        policy,
        [python, "-c", "bytearray(400 * 1024 * 1024)"],
        memory_mb=64,
        timeout=30,
    )

    assert outcome.state == "memory-limit"
    assert outcome.exit_code == 137


@pytest.mark.skipif(os.name != "nt", reason="лимит числа процессов есть только на Windows")
def test_process_limit_on_windows(policy: Policy, python: str) -> None:
    script = (
        "import subprocess, sys\n"
        "children = []\n"
        "try:\n"
        "    while True:\n"
        "        children.append(\n"
        "            subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(3)'])\n"
        "        )\n"
        "except OSError as exc:\n"
        "    print('stopped', getattr(exc, 'winerror', None))\n"
        "for child in children:\n"
        "    child.kill()\n"
    )
    outcome = _run(policy, [python, "-c", script], procs=2, timeout=30)

    assert outcome.ok
    output = outcome.stdout_path.read_text(encoding="utf-8")
    # 1816 = ERROR_NOT_ENOUGH_QUOTA: job-объект отказал в создании процесса.
    assert "stopped 1816" in output
    assert outcome.record["processes"] >= 1


def test_label_and_env_report(policy_factory, python: str) -> None:
    policy = policy_factory()
    outcome = run(
        RunRequest(argv=[python, "-c", "print(1)"], policy=policy, echo=False, label="demo")
    )

    assert outcome.record["label"] == "demo"
    assert "dropped" in outcome.record["env"]
    assert "GH_TOKEN" not in json.dumps(outcome.record["env"])


def test_memory_marker_detection(tmp_path: Path) -> None:
    from agentsandbox.runner import _memory_refused

    bad = tmp_path / "stderr.log"
    bad.write_text("Traceback...\nMemoryError\n", encoding="utf-8")
    assert _memory_refused(bad)

    other = tmp_path / "other.log"
    other.write_text("ValueError: не тот аргумент\n", encoding="utf-8")
    assert not _memory_refused(other)

    assert not _memory_refused(tmp_path / "missing.log")


def test_limits_are_recorded(policy: Policy, python: str) -> None:
    outcome = _run(policy, [python, "-c", "print(1)"], timeout=5, cpu=4, memory_mb=128)

    assert outcome.record["limits"] == {
        "timeout": 5.0,
        "cpu": 4.0,
        "memory_mb": 128,
        "procs": Limits().procs,
    }
