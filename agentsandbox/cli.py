"""CLI: run, audit verify / tail, doctor, policy."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, audit
from .config import ConfigError, Policy, load_policy
from .report import format_entry, format_outcome
from .runner import RunRequest, run

CAPABILITIES = (
    ("wall_time", "стенное время"),
    ("cpu_time", "процессорное время"),
    ("memory", "память"),
    ("processes", "число процессов"),
    ("kill_tree", "убийство дерева процессов"),
    ("filesystem_isolation", "изоляция файлов"),
    ("network_isolation", "изоляция сети"),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-sandbox",
        description="Запуск чужих скриптов с лимитами и журналом, который видно, если его правили",
    )
    parser.add_argument("--version", action="version", version=f"agent-sandbox {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="запустить команду под лимитами")
    run_parser.add_argument("--policy", "-p", help="файл политики TOML")
    run_parser.add_argument("--timeout", type=float, help="стенных секунд до убийства")
    run_parser.add_argument("--cpu", type=float, help="секунд процессорного времени")
    run_parser.add_argument("--memory", type=int, help="мегабайт памяти на задачу")
    run_parser.add_argument("--procs", type=int, help="предел числа процессов (Windows)")
    run_parser.add_argument("--cwd", help="рабочий каталог; по умолчанию — пустой каталог прогона")
    run_parser.add_argument("--label", help="метка прогона для журнала")
    run_parser.add_argument(
        "--no-echo", action="store_true", help="не показывать вывод в реальном времени"
    )
    run_parser.add_argument("--json", action="store_true", help="напечатать результат в JSON")
    run_parser.add_argument("cmd", nargs=argparse.REMAINDER, help="команда после --")

    audit_parser = sub.add_parser("audit", help="журнал прогонов")
    audit_sub = audit_parser.add_subparsers(dest="audit_command", required=True)
    verify = audit_sub.add_parser("verify", help="проверить цепочку хешей")
    verify.add_argument("--policy", "-p")
    verify.add_argument("--json", action="store_true")
    tail = audit_sub.add_parser("tail", help="последние записи")
    tail.add_argument("--policy", "-p")
    tail.add_argument("--limit", type=int, default=10)
    tail.add_argument("--json", action="store_true")

    doctor = sub.add_parser("doctor", help="что умеет эта машина")
    doctor.add_argument("--policy", "-p")
    doctor.add_argument("--json", action="store_true")

    policy_parser = sub.add_parser("policy", help="показать действующую политику")
    policy_parser.add_argument("--policy", "-p")
    policy_parser.add_argument("--json", action="store_true")

    return parser


def _load(args: argparse.Namespace) -> Policy:
    try:
        return load_policy(getattr(args, "policy", None))
    except ConfigError as exc:
        print(f"политика: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def cmd_run(args: argparse.Namespace, policy: Policy) -> int:
    command = [item for item in args.cmd]
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print('нужна команда, например: agent-sandbox run -- python -c "print(1)"', file=sys.stderr)
        return 2

    policy = policy.with_overrides(
        timeout=args.timeout,
        cpu=args.cpu,
        memory_mb=args.memory,
        procs=args.procs,
    )
    request = RunRequest(
        argv=command,
        policy=policy,
        cwd=Path(args.cwd).resolve() if args.cwd else None,
        echo=not args.no_echo and not args.json,
        label=args.label,
    )

    outcome = run(request)

    if args.json:
        print(json.dumps(outcome.as_dict(), ensure_ascii=False))
    else:
        if not args.no_echo:
            print()
        print(format_outcome(outcome))
    return outcome.exit_code


def cmd_audit(args: argparse.Namespace, policy: Policy) -> int:
    if args.audit_command == "verify":
        result = audit.verify(policy.audit_path)
        if args.json:
            print(json.dumps(result.as_dict(), ensure_ascii=False))
        elif result.ok:
            print(f"журнал цел: {result.entries} записей · {policy.audit_path}")
        else:
            print(
                f"журнал повреждён: {result.reason}, строка {result.bad_line} "
                f"(проверено {result.entries}) · {policy.audit_path}",
                file=sys.stderr,
            )
        return 0 if result.ok else 1

    entries = audit.read_entries(policy.audit_path, limit=args.limit)
    if args.json:
        print(json.dumps(entries, ensure_ascii=False))
    elif not entries:
        print(f"журнал пуст · {policy.audit_path}")
    else:
        print("\n".join(format_entry(entry) for entry in entries))
    return 0


def cmd_doctor(args: argparse.Namespace, policy: Policy) -> int:
    from .backends import get_backend

    backend = get_backend()
    capabilities = backend.probe()

    if args.json:
        payload = {"policy": _policy_dict(policy), "capabilities": capabilities}
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    print(f"agent-sandbox {__version__} · {sys.platform} · питон {sys.version.split()[0]}")
    print(f"backend: {capabilities.get('backend')}")
    for key, label in CAPABILITIES:
        mark = "да" if capabilities.get(key) else "нет"
        print(f"  {label:<26} {mark}")
    print()
    print(f"политика: {policy.source or 'значения по умолчанию'}")
    print(f"  таймаут {policy.limits.timeout:g} с · cpu {policy.limits.cpu:g} с · "
          f"память {policy.limits.memory_mb} МБ · процессов {policy.limits.procs}")
    print(f"  разрешено: {', '.join(policy.allow_programs) or 'всё'}")
    print(f"  журнал:    {policy.audit_path}")
    print(f"  прогоны:   {policy.runs_dir}")
    return 0


def _policy_dict(policy: Policy) -> dict[str, object]:
    return {
        "source": str(policy.source) if policy.source else None,
        "digest": policy.audit_digest,
        "limits": policy.limits.as_dict(),
        "allow_programs": list(policy.allow_programs),
        "env_keep": list(policy.env_keep),
        "audit_path": str(policy.audit_path),
        "runs_dir": str(policy.runs_dir),
    }


def cmd_policy(args: argparse.Namespace, policy: Policy) -> int:
    if args.json:
        print(json.dumps(_policy_dict(policy), ensure_ascii=False, indent=2))
        return 0
    print(f"источник:  {policy.source or 'по умолчанию'}")
    print(f"отпечаток: {policy.audit_digest}")
    print(f"лимиты:    таймаут {policy.limits.timeout:g} с · cpu {policy.limits.cpu:g} с · "
          f"память {policy.limits.memory_mb} МБ · процессов {policy.limits.procs}")
    print(f"разрешено: {', '.join(policy.allow_programs) or 'всё (allow_programs пуст)'}")
    print(f"env keep:  {', '.join(policy.env_keep)}")
    print(f"журнал:    {policy.audit_path}")
    print(f"прогоны:   {policy.runs_dir}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    policy = _load(args)

    if args.command == "run":
        return cmd_run(args, policy)
    if args.command == "audit":
        return cmd_audit(args, policy)
    if args.command == "doctor":
        return cmd_doctor(args, policy)
    if args.command == "policy":
        return cmd_policy(args, policy)
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
