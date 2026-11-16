"""Политика и лимиты: значения по умолчанию, проверки, TOML."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsandbox.config import DEFAULT_ALLOW, ConfigError, Limits, Policy, load_policy


def test_defaults_are_sane() -> None:
    limits = Limits()
    assert limits.timeout > 0
    assert limits.cpu > 0
    assert limits.memory_mb >= 16
    assert limits.procs >= 1


@pytest.mark.parametrize(
    ("field", "value"),
    [("timeout", 0), ("timeout", -1), ("cpu", 0), ("memory_mb", 8), ("procs", 0)],
)
def test_bad_limits_rejected(field: str, value: float) -> None:
    with pytest.raises(ConfigError):
        Limits(**{field: value})


def test_digest_tracks_limits() -> None:
    base = Limits()
    assert Policy(limits=base).audit_digest == Policy(limits=base).audit_digest
    changed = Policy(limits=Limits(timeout=base.timeout + 1))
    assert changed.audit_digest != Policy(limits=base).audit_digest


def test_program_allowed_is_deny_by_default() -> None:
    policy = Policy()
    assert policy.program_allowed("python")
    assert policy.program_allowed("python3")
    assert not policy.program_allowed("curl")
    assert not policy.program_allowed("C:/tools/curl.exe")


def test_empty_allow_list_means_everything() -> None:
    assert Policy(allow_programs=()).program_allowed("любая-программа")


def test_exe_suffix_ignored() -> None:
    policy = Policy(allow_programs=("python",))
    assert policy.program_allowed("python.exe")
    assert policy.program_allowed(r"C:\Python312\PYTHON.EXE")


def test_overrides_ignore_none_and_keep_the_rest() -> None:
    policy = Policy()
    updated = policy.with_overrides(timeout=5, memory_mb=256, procs=None)
    assert updated.limits.timeout == 5
    assert updated.limits.memory_mb == 256
    assert updated.limits.procs == policy.limits.procs
    assert updated.limits.cpu == policy.limits.cpu
    assert updated.allow_programs == policy.allow_programs


def test_load_policy_resolves_paths_from_file(tmp_path: Path) -> None:
    config = tmp_path / "cfg" / "sandbox.toml"
    config.parent.mkdir()
    config.write_text(
        """
[limits]
timeout = 7
cpu = 3
memory_mb = 256
procs = 4

[policy]
allow_programs = ["python"]
env_keep = ["PATH"]

[paths]
audit = "var/audit.jsonl"
runs = "var/runs"
""",
        encoding="utf-8",
    )

    policy = load_policy(config)

    assert policy.limits.timeout == 7
    assert policy.limits.cpu == 3
    assert policy.allow_programs == ("python",)
    assert policy.env_keep == ("PATH",)
    assert policy.audit_path == (config.parent / "var" / "audit.jsonl").resolve()
    assert policy.runs_dir == (config.parent / "var" / "runs").resolve()
    assert policy.source == config.resolve()


def test_missing_policy_file() -> None:
    with pytest.raises(ConfigError, match="нет файла политики"):
        load_policy("nope-does-not-exist.toml")


def test_broken_toml(tmp_path: Path) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text("[limits\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="TOML"):
        load_policy(bad)


def test_bom_in_policy_file_is_tolerated(tmp_path: Path) -> None:
    config = tmp_path / "bom.toml"
    config.write_text('[limits]\ntimeout = 4\n', encoding="utf-8-sig", newline="\n")

    assert load_policy(config).limits.timeout == 4


def test_defaults_used_when_sections_absent(tmp_path: Path) -> None:
    empty = tmp_path / "empty.toml"
    empty.write_text("", encoding="utf-8")
    policy = load_policy(empty)
    assert policy.limits == Limits()
    assert policy.allow_programs == DEFAULT_ALLOW
