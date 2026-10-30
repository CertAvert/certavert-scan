"""Command line: what runs when someone types `certavert-scan`.

`main()` does the whole run, in this order:

1. Read the options (`build_parser()`).
2. Find the settings: the command line, then the settings file, then the
   defaults. With no settings file and no targets, this is the first run:
   write a settings file for this network and ask before scanning
   (`_first_run()`).
3. Turn the targets into endpoints (`targets.expand()`).
4. Probe them, many at a time (`run_scan()` → `probe.probe()`).
5. Write the HTML, CSV and JSON files (`output`).

The only machines contacted are the ones being scanned, plus the DNS server
for names. Nothing is sent to CertAvert or anyone else.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from typing import Any, Optional

from certavert_scan import __version__, config, output, probe, targets

# Shown at the end of `certavert-scan --help`.
EXAMPLES = """\
examples:
  certavert-scan                      (first run: writes a settings file for this network)
  certavert-scan 10.0.0.0/24
  certavert-scan 10.0.0.0/24 192.168.1.10:8443 intranet.example.local
  certavert-scan --file targets.txt --exclude 10.0.0.1,10.0.5.0/28
  certavert-scan 10.0.0.0/22 --ports 443,8443,9000-9010 --workers 16

Only scan networks you own or are allowed to scan.
"""


def build_parser() -> argparse.ArgumentParser:
    """The command line options.

    Options that the settings file also has default to None here, so `main()`
    can tell "not given" (use the file's value) from "given" (wins over the file).
    """
    parser = argparse.ArgumentParser(
        prog="certavert-scan",
        description="Find the TLS certificates on your network and see when they expire. "
        "Writes HTML, CSV and JSON files on this machine; nothing is sent anywhere.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="*", metavar="TARGET", help="network (10.0.0.0/24), address or host name, optionally with :port")
    parser.add_argument("-c", "--config", metavar="FILE", help=f"settings file (default: ./{config.FILE_NAME}, then {config.user_config_path()})")
    parser.add_argument("--no-config", action="store_true", help="ignore the settings file")
    parser.add_argument("--init", nargs="?", const=config.FILE_NAME, metavar="FILE", help=f"write a settings file for this network and stop (default: ./{config.FILE_NAME})")
    parser.add_argument("-y", "--yes", action="store_true", help="on the first run, scan without asking")
    parser.add_argument("-f", "--file", action="append", default=[], metavar="FILE", help="read targets from a file (one or more per line, # for comments)")
    parser.add_argument("-p", "--ports", help=f"ports for targets without one (default: {','.join(map(str, targets.DEFAULT_PORTS))})")
    parser.add_argument("-x", "--exclude", action="append", default=[], metavar="ADDRESSES", help="addresses or networks to skip, comma-separated (added to the file's)")
    parser.add_argument("-o", "--output", metavar="DIR", help="folder for the files (default: current folder)")
    parser.add_argument("--name", default=None, help="file name without extension (default: certavert-scan-YYYYMMDD-HHMMSS)")
    parser.add_argument("--format", help="files to write: html, csv, json (default: all three)")
    parser.add_argument("-w", "--workers", type=int, help="connections at the same time (default: 32)")
    parser.add_argument("-t", "--timeout", type=float, help="seconds per connection step (default: 3)")
    parser.add_argument("--expiring-days", type=int, help="days left counted as Expiring (default: 30)")
    parser.add_argument("--max-addresses", type=int, help=f"refuse to scan more addresses than this (default: {targets.DEFAULT_MAX_ADDRESSES})")
    parser.add_argument("--no-reverse-dns", action="store_true", help="don't look up names for addresses that answer")
    parser.add_argument("-q", "--quiet", action="store_true", help="no progress, only errors")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser


class Progress:
    """The "1234/2286 checked, 14 found" line. Only shown in a terminal, so it
    never ends up in a log file when run from cron or Task Scheduler."""

    def __init__(self, total: int, quiet: bool) -> None:
        self.total, self.done, self.found = total, 0, 0
        self.enabled = not quiet and sys.stderr.isatty()
        self.last = 0.0

    def step(self, found: bool) -> None:
        self.done += 1
        self.found += found
        now = time.monotonic()
        if self.enabled and (now - self.last > 0.2 or self.done == self.total):
            self.last = now
            sys.stderr.write(f"\r  {self.done}/{self.total} checked, {self.found} found ")
            sys.stderr.flush()

    def end(self) -> None:
        if self.enabled:
            sys.stderr.write("\n")


def run_scan(
    endpoints, total: int, workers: int, timeout: float, expiring_days: int, reverse_dns: bool, progress: Progress
) -> list[dict[str, Any]]:
    """Probe every endpoint, `workers` at a time, and return the results.

    Endpoints are taken from the iterator a few at a time (at most 4 × workers
    waiting), so a /16 with 600,000 endpoints never sits in memory at once.
    """
    results: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    iterator = iter(endpoints)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = set()

        def fill() -> None:
            while len(pending) < workers * 4:
                try:
                    endpoint = next(iterator)
                except StopIteration:
                    return
                pending.add(pool.submit(probe.probe, endpoint, timeout, expiring_days, reverse_dns, now))

        fill()
        while pending:
            finished, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in finished:
                pending.discard(future)
                result = future.result()
                if result is not None:
                    results.append(result)
                progress.step(bool(result and result.get("certificate")))
            fill()
    progress.end()
    return results


def _fail(message: str) -> int:
    """Print an error and return exit code 2 (wrong input; nothing was scanned)."""
    print(f"certavert-scan: {message}", file=sys.stderr)
    return 2


def _ask(question: str) -> bool:
    """A yes/no question. Anything but "y" or "yes" is no."""
    try:
        return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def _show_settings(path: str, settings: dict[str, Any]) -> None:
    """Show where the settings file is and what it will scan."""
    ports = ", ".join(str(p) for p in settings["ports"])
    print(f"Settings: {path}", file=sys.stderr)
    print(f"  Targets: {', '.join(settings['targets']) or '(none)'}", file=sys.stderr)
    print(f"  Ports:   {ports}", file=sys.stderr)
    print(f"  Results: {settings['output'] or config.default_output()}", file=sys.stderr)


def _first_run(args: argparse.Namespace, path: str) -> Optional[dict[str, Any]]:
    """Write the user's settings file. Return the settings to scan with, or None to stop."""
    networks = config.local_networks()
    config.write_template(path, networks, config.default_output())
    settings = config.load(path)
    print("First run: wrote a settings file for this network.", file=sys.stderr)
    _show_settings(path, settings)
    if not networks:
        print("No private network found on this machine: add yours to the file, then run certavert-scan again.", file=sys.stderr)
        return None
    if args.yes:
        return settings
    if not sys.stdin.isatty():
        print("Check the file, then run certavert-scan again (or add --yes).", file=sys.stderr)
        return None
    if _ask(f"Scan {', '.join(networks)} now?"):
        return settings
    print("Change the file if you need to, then run certavert-scan again.", file=sys.stderr)
    return None


def main(argv: Optional[list[str]] = None) -> int:
    """Run the tool. Returns the exit code: 0 done, 2 wrong input, 130 stopped with Ctrl+C."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # --init: only write a settings file.
    if args.init:
        if os.path.exists(args.init):
            return _fail(f"{args.init} already exists")
        try:
            config.write_template(args.init, config.local_networks(), config.default_output())
        except OSError as error:
            return _fail(f"could not write {args.init}: {error.strerror or error}")
        print(f"Wrote {args.init}. Change it if you need to, then run certavert-scan.", file=sys.stderr)
        return 0

    # Settings: the file given with --config, else ./certavert-scan.toml, else
    # the user's own; with none of them and no targets, the first run.
    try:
        settings = dict(config.DEFAULTS)
        config_path = None if args.no_config else (args.config or config.find())
        if args.config and not os.path.isfile(args.config):
            return _fail(f"{args.config}: no such file")
        if config_path:
            settings = config.load(config_path)
        elif not args.no_config and not args.targets and not args.file:
            settings_or_none = _first_run(args, config.user_config_path())
            if settings_or_none is None:
                return 0
            settings, config_path = settings_or_none, config.user_config_path()
    except (config.ConfigError, OSError) as error:
        return _fail(str(error))

    try:
        # Targets on the command line replace the file's; excludes add to them.
        raw_targets = list(args.targets)
        for path in args.file:
            raw_targets += targets.read_targets_file(path)
        if not raw_targets:
            raw_targets = list(settings["targets"])
        if not raw_targets:
            where = f" (or add them to {config_path})" if config_path else ""
            parser.error(f"give at least one target: a network, an address or a host name{where}")
        parsed = [targets.parse_target(t) for t in raw_targets]
        ports_text = args.ports or ",".join(str(p) for p in settings["ports"])
        ports = targets.parse_ports(ports_text)
        excludes = targets.parse_excludes(list(settings["exclude"]) + args.exclude)
        formats_text = args.format or ",".join(settings["formats"])
        formats = [f.strip().lower() for f in formats_text.split(",") if f.strip()]
    except (targets.TargetError, OSError) as error:
        prefix = f"{config_path}: " if config_path and not args.targets and not args.file else ""
        return _fail(f"{prefix}{error}")

    # Every other setting: the command line if given, else the file (or default).
    output_dir = args.output or settings["output"] or config.default_output()
    workers = args.workers if args.workers is not None else settings["workers"]
    timeout = args.timeout if args.timeout is not None else float(settings["timeout"])
    expiring_days = args.expiring_days if args.expiring_days is not None else settings["expiring_days"]
    max_addresses = args.max_addresses if args.max_addresses is not None else settings["max_addresses"]
    reverse_dns = settings["reverse_dns"] and not args.no_reverse_dns

    # Check everything before connecting to anything.
    bad = [f for f in formats if f not in ("html", "csv", "json")]
    if bad or not formats:
        return _fail(f"unknown format: {', '.join(bad) or '(none)'}")
    if workers < 1 or workers > 512:
        return _fail("workers must be between 1 and 512")
    if timeout <= 0:
        return _fail("timeout must be more than 0")

    addresses = sum(t.size() for t in parsed)
    if addresses > max_addresses:
        return _fail(
            f"{addresses:,} addresses is more than the limit of {max_addresses:,}. "
            "Scan smaller networks, or raise it with --max-addresses (max_addresses in the settings file)."
        )

    total = targets.endpoint_count(parsed, ports)
    if not args.quiet:
        print(f"Scanning {addresses:,} address{'es' if addresses != 1 else ''}, {total:,} endpoint{'s' if total != 1 else ''}…", file=sys.stderr)

    # Scan.
    started = datetime.now(timezone.utc)
    unresolved: list[str] = []
    progress = Progress(total, args.quiet)
    try:
        results = run_scan(
            targets.expand(parsed, ports, excludes, unresolved),
            total,
            workers,
            timeout,
            expiring_days,
            reverse_dns,
            progress,
        )
    except KeyboardInterrupt:
        print("\ncertavert-scan: stopped", file=sys.stderr)
        return 130
    finished = datetime.now(timezone.utc)

    # Names DNS didn't know are listed too, so a typo in the targets shows.
    for name in unresolved:
        results.append(
            {
                "endpoint": name,
                "address": "",
                "port": 0,
                "name": name,
                "reverse_dns": None,
                "status": "Error",
                "error": "Name not found in DNS",
                "tls_version": None,
                "cipher": None,
                "issues": [],
                "certificate": None,
                "chain": [],
            }
        )

    # What was scanned and how, saved with the results (the JSON's "scan").
    scan = {
        "started_at": started.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "finished_at": finished.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "targets": raw_targets,
        "targets_text": ", ".join(raw_targets) if len(raw_targets) <= 5 else f"{len(raw_targets)} targets",
        "ports": list(ports),
        "ports_text": ports_text if len(ports) <= 12 else f"{len(ports)} ports",
        "excluded": [str(n) for n in excludes],
        "expiring_days": expiring_days,
    }
    doc = output.document(results, scan)

    # Write the files. A new name each run (date and time), so nothing is overwritten.
    base = args.name or f"certavert-scan-{started:%Y%m%d-%H%M%S}"
    written = []
    try:
        os.makedirs(output_dir, exist_ok=True)
        writers = {"json": output.to_json, "csv": output.to_csv, "html": output.to_html}
        for fmt in formats:
            path = os.path.join(output_dir, f"{base}.{fmt}")
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(writers[fmt](doc))
            written.append(path)
    except OSError as error:
        print(f"certavert-scan: could not write the files: {error}", file=sys.stderr)
        return 2

    # The summary line and where the files are.
    if not args.quiet:
        s = doc["summary"]
        parts = [f"{s[k]} {k.lower()}" for k in ("Expired", "Expiring", "OK", "Error") if s.get(k)]
        found = f"{s['endpoints']} endpoint{'s' if s['endpoints'] != 1 else ''}"
        print(f"Found {found}, {s['certificates']} certificate{'s' if s['certificates'] != 1 else ''}" + (f": {', '.join(parts)}" if parts else ""), file=sys.stderr)
        for path in written:
            print(f"  {path}", file=sys.stderr)
    return 0
