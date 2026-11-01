"""Command line interface.

    certwatch example.com
    certwatch example.com:8443
    certwatch --file hosts.txt --json
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List, Optional, Tuple

from . import __version__
from .audit import Severity, audit_host

_COLOURS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[2m",
}
_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def parse_target(text: str, default_port: int = 443) -> Tuple[str, int]:
    """Accept host, host:port, [v6]:port and https://host/path forms."""
    value = text.strip()
    if not value:
        raise ValueError("empty target")

    for scheme in ("https://", "http://", "tls://"):
        if value.lower().startswith(scheme):
            value = value[len(scheme) :]
            break

    value = value.split("/")[0]

    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise ValueError(f"unterminated IPv6 literal: {text!r}")
        host = value[1:end]
        rest = value[end + 1 :]
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, default_port

    if value.count(":") == 1:
        host, _, port_text = value.partition(":")
        if not port_text.isdigit():
            raise ValueError(f"bad port in {text!r}")
        return host, int(port_text)

    # Zero colons (hostname) or many (unbracketed IPv6): both mean no port given.
    return value, default_port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="certwatch",
        description=(
            "Audit a host's TLS configuration: certificate, chain, expiry, "
            "negotiable protocol versions and weak cipher suites. Read-only; "
            "it performs handshakes and nothing else."
        ),
    )
    parser.add_argument("targets", nargs="*", help="host or host:port")
    parser.add_argument("--file", type=Path, help="read targets from a file, one per line")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-connection timeout")
    parser.add_argument(
        "--no-cipher-probe",
        action="store_true",
        help="skip weak-cipher probes (faster, fewer connections)",
    )
    parser.add_argument(
        "--workers", type=int, default=8, help="concurrent hosts (default 8)"
    )
    parser.add_argument(
        "--min-severity",
        default="info",
        choices=[s.value for s in Severity],
        help="hide findings below this level",
    )
    parser.add_argument("--no-colour", action="store_true")
    parser.add_argument("--version", action="version", version=f"certwatch {__version__}")
    return parser


def collect_targets(args) -> List[Tuple[str, int]]:
    raw: List[str] = list(args.targets)
    if args.file:
        try:
            text = args.file.read_text()
        except OSError as exc:
            print(f"error reading target file: {exc}", file=sys.stderr)
            return []
        for line in text.splitlines():
            stripped = line.split("#")[0].strip()
            if stripped:
                raw.append(stripped)

    targets: List[Tuple[str, int]] = []
    for item in raw:
        try:
            targets.append(parse_target(item))
        except (ValueError, TypeError) as exc:
            print(f"skipping {item!r}: {exc}", file=sys.stderr)
    return targets


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    targets = collect_targets(args)

    if not targets:
        parser.print_help()
        return 2

    def run(pair: Tuple[str, int]):
        host, port = pair
        return audit_host(
            host,
            port,
            timeout=args.timeout,
            probe_weak_ciphers=not args.no_cipher_probe,
        )

    if len(targets) == 1:
        results = [run(targets[0])]
    else:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            results = list(pool.map(run, targets))

    min_rank = Severity(args.min_severity).rank
    for result in results:
        result.findings = [f for f in result.findings if f.severity.rank >= min_rank]

    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        colour = not args.no_colour and sys.stdout.isatty()
        for result in results:
            _print_result(result, colour)

    # Exit 1 when anything high or above remains, so a cron job can alert on it.
    for result in results:
        highest = result.highest_severity
        if highest is not None and highest.rank >= Severity.HIGH.rank:
            return 1
    return 0


def _print_result(result, colour: bool) -> None:
    where = f"{result.host}:{result.port}"
    if not result.reachable:
        print(f"{where}  UNREACHABLE  {result.error}")
        return

    cert = result.cert
    print(f"{where}  {result.negotiated_protocol}  {result.negotiated_cipher}")
    if cert is not None:
        days = cert.days_remaining
        remaining = f"{days} days" if days is not None else "unknown"
        print(f"  subject: {cert.subject}")
        print(f"  issuer:  {cert.issuer}")
        print(f"  expires: {cert.not_after} ({remaining})")

    offered = [name for name, ok in result.protocols.items() if ok]
    print(f"  protocols: {', '.join(offered) if offered else 'none'}")

    if not result.findings:
        print("  no findings\n")
        return

    print()
    for finding in sorted(result.findings, key=lambda f: -f.severity.rank):
        label = _LABEL[finding.severity.value]
        if colour:
            label = f"{_COLOURS[finding.severity.value]}{label}\033[0m"
        print(f"  [{label}] {finding.title}")
        print(f"          {finding.detail}")
        if finding.remediation:
            print(f"          fix: {finding.remediation}")
    print()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
