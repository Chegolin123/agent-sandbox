"""Общие приспособления для тестов."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from agentsandbox.config import Limits, Policy


def _build_policy(base: Path, allow_programs: tuple[str, ...] = (), **limits) -> Policy:
    """Политика с каталогами внутри временного каталога теста."""
    return Policy(
        limits=Limits(**limits) if limits else Limits(),
        allow_programs=allow_programs,
        audit_path=base / "audit" / "audit.jsonl",
        runs_dir=base / "runs",
    )


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    (tmp_path / "work").mkdir()
    return tmp_path


@pytest.fixture
def policy_factory(workdir: Path) -> Callable[..., Policy]:
    def build(**options) -> Policy:
        return _build_policy(workdir, **options)

    return build


@pytest.fixture
def policy(policy_factory: Callable[..., Policy]) -> Policy:
    return policy_factory()


@pytest.fixture
def python() -> str:
    return sys.executable
