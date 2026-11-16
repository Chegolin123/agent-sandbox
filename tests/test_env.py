"""Очистка окружения: минимум переменных и ни одного секрета."""

from __future__ import annotations

import os

import pytest

from agentsandbox import env as env_module


@pytest.mark.parametrize(
    "name",
    [
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "HF_TOKEN",
        "MY_SECRET_VALUE",
        "DB_PASSWORD",
        "SESSION_COOKIE",
        "AUTHORIZATION_HEADER",
        "PRIVATE_KEY_PATH",
    ],
)
def test_secrets_recognised(name: str) -> None:
    assert env_module.is_secret(name)


@pytest.mark.parametrize("name", ["PATH", "LANG", "TERM", "TEMP", "HOME"])
def test_ordinary_variables_are_not_secrets(name: str) -> None:
    assert not env_module.is_secret(name)


def test_prepare_keeps_base_and_drops_secrets() -> None:
    source = {
        "PATH": "/bin:/usr/bin",
        "GH_TOKEN": "ghp_secret",
        "PATH_TO_TOKEN": "/x",
    }
    prepared = env_module.prepare(source)
    assert prepared.values["PATH"] == "/bin:/usr/bin"
    assert "GH_TOKEN" not in prepared.values
    assert "PATH_TO_TOKEN" not in prepared.values
    assert "GH_TOKEN" in prepared.dropped


@pytest.mark.skipif(os.name != "posix", reason="LANG входит в базовые только на POSIX")
def test_lang_kept_on_posix() -> None:
    prepared = env_module.prepare({"PATH": "/bin", "LANG": "C.UTF-8"})
    assert prepared.values["LANG"] == "C.UTF-8"


@pytest.mark.skipif(os.name != "nt", reason="PATHEXT нужен только на Windows")
def test_pathext_kept_on_windows() -> None:
    prepared = env_module.prepare({"PATH": "C:/x", "PATHEXT": ".EXE;.BAT"})
    assert prepared.values["PATHEXT"] == ".EXE;.BAT"


def test_policy_cannot_ask_for_a_secret() -> None:
    prepared = env_module.prepare({"PATH": "/bin", "DEPLOY_TOKEN": "x"}, keep=("DEPLOY_TOKEN",))
    assert "DEPLOY_TOKEN" not in prepared.values
    assert "DEPLOY_TOKEN" in prepared.dropped


def test_extra_variables_from_policy_are_kept() -> None:
    prepared = env_module.prepare({"PATH": "/bin", "MY_FLAG": "1"}, keep=("MY_FLAG",))
    assert prepared.values["MY_FLAG"] == "1"
    assert prepared.kept_extra == ["MY_FLAG"]


def test_temp_dir_is_redirected() -> None:
    prepared = env_module.prepare({"PATH": "/bin", "TEMP": "/old"}, temp_dir="/run/tmp")
    for name in ("TEMP", "TMP", "TMPDIR"):
        assert prepared.values[name] == "/run/tmp"


def test_python_is_told_not_to_touch_the_user_site() -> None:
    prepared = env_module.prepare({"PATH": "/bin"})
    assert prepared.values["PYTHONNOUSERSITE"] == "1"
    assert prepared.values["PYTHONUNBUFFERED"] == "1"
    assert prepared.values["PYTHONDONTWRITEBYTECODE"] == "1"


@pytest.mark.skipif(os.name != "posix", reason="HOME подставляется только на POSIX")
def test_home_set_on_posix() -> None:
    prepared = env_module.prepare({"PATH": "/bin"}, temp_dir="/run/tmp")
    assert prepared.values["HOME"] == "/run/tmp"
