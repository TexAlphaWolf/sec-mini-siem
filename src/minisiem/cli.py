"""Command line interface: `minisiem serve | ingest | purge | rules check | rules export`."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from .config import load_settings
from .db import init_db, make_session_factory
from .parsers import PARSERS
from .pipeline import Pipeline
from .retention import purge_older_than
from .rules import RuleError, load_rules
from .sigma import export_sigma


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    # One worker on purpose: detection state is kept in memory (see docs/architecture.md).
    uvicorn.run("minisiem.api:create_app", factory=True, host=args.host, port=args.port, workers=1)
    return 0


def _cmd_rules_check(args: argparse.Namespace) -> int:
    directory = Path(args.directory) if args.directory else load_settings().rules_dir
    try:
        rules = load_rules(directory)
    except RuleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"{len(rules)} rules OK in {directory}")
    for rule in rules:
        kind = "threshold" if rule.threshold else "single"
        print(f"  {rule.severity:<8} {rule.id:<28} {kind:<9} {rule.title}")
    return 0


def _cmd_rules_export(args: argparse.Namespace) -> int:
    directory = Path(args.directory) if args.directory else load_settings().rules_dir
    try:
        text = export_sigma(load_rules(directory))
    except RuleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        sys.stdout.write(text)
    return 0


def _read_new(path: Path, position: int) -> tuple[list[str], int]:
    """Read complete lines appended to `path` since `position`; handles rotation/truncation."""
    size = path.stat().st_size
    if size < position:
        position = 0  # the file was truncated or rotated
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(position)
        data = handle.read()
        end = handle.tell()
    if not data:
        return [], position
    if not data.endswith("\n"):  # keep a partially written last line for next time
        head, _, tail = data.rpartition("\n")
        return head.splitlines(), end - len(tail.encode("utf-8"))
    return data.splitlines(), end


def _cmd_ingest(args: argparse.Namespace) -> int:
    settings = load_settings()
    try:
        rules = load_rules(settings.rules_dir)
    except RuleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    engine, session_factory = make_session_factory(settings.database_url)
    try:
        init_db(engine)
        return _ingest(args, Pipeline(session_factory, rules, settings.log_timezone))
    finally:
        engine.dispose()


def _cmd_purge(args: argparse.Namespace) -> int:
    settings = load_settings()
    days = args.days if args.days is not None else settings.retention_days
    if days < 1:
        print("error: pass --days N or set MINISIEM_RETENTION_DAYS", file=sys.stderr)
        return 1
    engine, session_factory = make_session_factory(settings.database_url)
    try:
        init_db(engine)
        events, alerts = purge_older_than(session_factory, days)
    finally:
        engine.dispose()
    print(f"deleted events={events} alerts={alerts} older than {days} days")
    return 0


def _ingest(args: argparse.Namespace, pipeline: Pipeline) -> int:
    def report(result) -> None:  # noqa: ANN001
        print(f"parsed={result.parsed} skipped={result.skipped} alerts={result.alerts}")

    if args.file == "-":
        report(pipeline.ingest(args.source, sys.stdin, year=args.year))
        return 0

    path = Path(args.file)
    if not path.is_file():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 1

    if args.follow:
        pipeline.restore_state()  # a long-running follower continues where the last run stopped
    lines, position = _read_new(path, 0)
    report(pipeline.ingest(args.source, lines, year=args.year))
    if not args.follow:
        return 0

    print(f"following {path} (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1.0)
            lines, position = _read_new(path, position)
            if lines:
                report(pipeline.ingest(args.source, lines, year=args.year))
    except KeyboardInterrupt:
        return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="minisiem", description="A small, readable SIEM.")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the API and dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.set_defaults(func=_cmd_serve)

    ingest = sub.add_parser("ingest", help="parse a log file straight into the database")
    ingest.add_argument("source", choices=sorted(PARSERS))
    ingest.add_argument("file", help="path to the log file, or - for stdin")
    ingest.add_argument(
        "--follow", action="store_true", help="keep reading new lines (like tail -f)"
    )
    ingest.add_argument("--year", type=int, help="year for syslog lines (default: current year)")
    ingest.set_defaults(func=_cmd_ingest)

    purge = sub.add_parser("purge", help="delete events and alerts older than N days")
    purge.add_argument("--days", type=int, help="age limit (default: $MINISIEM_RETENTION_DAYS)")
    purge.set_defaults(func=_cmd_purge)

    rules = sub.add_parser("rules", help="work with detection rules")
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)
    check = rules_sub.add_parser("check", help="validate rule files")
    check.add_argument(
        "directory", nargs="?", help="rules directory (default: $MINISIEM_RULES_DIR)"
    )
    check.set_defaults(func=_cmd_rules_check)
    export = rules_sub.add_parser("export", help="export the rules in Sigma format")
    export.add_argument(
        "directory", nargs="?", help="rules directory (default: $MINISIEM_RULES_DIR)"
    )
    export.add_argument("-o", "--output", help="write to this file instead of the screen")
    export.set_defaults(func=_cmd_rules_export)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
