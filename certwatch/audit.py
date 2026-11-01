"""TLS configuration auditing.

Everything here is stdlib ``ssl`` and ``socket``. That is a deliberate
constraint: a scanner that needs a 40 MB dependency tree to check a certificate
is a scanner nobody runs from a jump host at 3am.

What this module can therefore see, and what it cannot, is spelled out in
``docs/limitations.md``. The short version: it observes what the handshake
exposes, and decodes the certificate DER with the local parser in ``der.py``
because ``getpeercert()`` returns nothing when verification is off.
"""

from __future__ import annotations

import datetime as _dt
import socket
import ssl
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

from .der import DERError, parse_certificate


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        # These MUST be defined explicitly. Severity subclasses str, so without
        # __gt__ the comparison falls through to str.__gt__ and orders by the
        # literal text: "critical" < "medium" alphabetically. That silently
        # inverts severity ordering in every `>` / `>=` comparison.
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    detail: str
    remediation: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    not_before: Optional[_dt.datetime] = None
    not_after: Optional[_dt.datetime] = None
    serial: str = ""
    sans: List[str] = field(default_factory=list)
    version: int = 0
    signature_algorithm: str = ""
    key_algorithm: str = ""
    key_bits: int = 0
    sha256_fingerprint: str = ""
    is_ca: bool = False

    @property
    def days_remaining(self) -> Optional[int]:
        if self.not_after is None:
            return None
        now = _dt.datetime.now(_dt.timezone.utc)
        return int((self.not_after - now).total_seconds() // 86400)

    def to_dict(self) -> Dict[str, object]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "days_remaining": self.days_remaining,
            "serial": self.serial,
            "sans": self.sans,
            "version": self.version,
            "signature_algorithm": self.signature_algorithm,
            "key_algorithm": self.key_algorithm,
            "key_bits": self.key_bits,
            "sha256_fingerprint": self.sha256_fingerprint,
            "is_ca": self.is_ca,
        }


@dataclass
class AuditResult:
    host: str
    port: int
    reachable: bool = False
    error: str = ""
    cert: Optional[CertInfo] = None
    protocols: Dict[str, bool] = field(default_factory=dict)
    negotiated_protocol: str = ""
    negotiated_cipher: str = ""
    cipher_bits: int = 0
    weak_ciphers_accepted: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> Dict[str, object]:
        return {
            "host": self.host,
            "port": self.port,
            "reachable": self.reachable,
            "error": self.error,
            "cert": self.cert.to_dict() if self.cert else None,
            "protocols": self.protocols,
            "negotiated_protocol": self.negotiated_protocol,
            "negotiated_cipher": self.negotiated_cipher,
            "cipher_bits": self.cipher_bits,
            "weak_ciphers_accepted": self.weak_ciphers_accepted,
            "findings": [f.to_dict() for f in self.findings],
            "highest_severity": (
                self.highest_severity.value if self.highest_severity else None
            ),
        }


# Ordered oldest to newest. SSLv3 and TLS 1.0/1.1 are probed explicitly: many
# servers still accept them, and that is the most common real finding.
_PROTOCOLS: Sequence[Tuple[str, object]] = (
    ("SSLv3", getattr(ssl.TLSVersion, "SSLv3", None)),
    ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
    ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
)

_WEAK_CIPHERS: Sequence[str] = (
    "RC4-SHA",
    "RC4-MD5",
    "DES-CBC3-SHA",
    "DES-CBC-SHA",
    "NULL-SHA",
    "NULL-MD5",
    "EXP-RC4-MD5",
    "ADH-AES128-SHA",
    "AECDH-AES128-SHA",
)


def parse_cert_time(value: str) -> Optional[_dt.datetime]:
    """Parse an OpenSSL cert timestamp.

    OpenSSL pads single-digit days with spaces ("Jun  1 12:00:00 2027 GMT"), so
    the parse must tolerate that. A strict "%b %d" rejects it, and the failure
    would silently lose the expiry date - the most important field in a report.
    """
    cleaned = " ".join(value.split())
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return _dt.datetime.strptime(cleaned, fmt).replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            continue
    return None


def format_name(parts) -> str:
    """Flatten the tuple-of-tuples OpenSSL returns for a distinguished name."""
    if not parts:
        return ""
    pieces = []
    for rdn in parts:
        for key, value in rdn:
            pieces.append(f"{key}={value}")
    return ", ".join(pieces)


def cert_from_peercert(raw: dict) -> CertInfo:
    """Build CertInfo from getpeercert()'s verified-mode dict.

    Only used when verification succeeded, because getpeercert() returns {} in
    every other mode. The normal path is cert_from_der(), below.
    """
    sans = [f"{kind}:{value}" for kind, value in raw.get("subjectAltName", ())]
    return CertInfo(
        subject=format_name(raw.get("subject")),
        issuer=format_name(raw.get("issuer")),
        not_before=parse_cert_time(raw.get("notBefore", "")),
        not_after=parse_cert_time(raw.get("notAfter", "")),
        serial=str(raw.get("serialNumber", "")),
        sans=sans,
        version=raw.get("version", 0) or 0,
    )


def cert_from_der(der: bytes) -> Optional[CertInfo]:
    """Decode the certificate from its DER encoding.

    This is the primary path. ``getpeercert()`` returns an empty dict whenever
    verification is off, which is how this tool scans, so relying on it meant
    every report silently omitted the expiry date -- the single most important
    field a certificate tool exists to report.

    Returns None when the bytes cannot be decoded, so an unusual certificate
    degrades the report instead of crashing the scan.
    """
    try:
        parsed = parse_certificate(der)
    except (DERError, Exception):  # noqa: BLE001 - never fail a scan on one cert
        return None
    return CertInfo(
        subject=parsed.subject,
        issuer=parsed.issuer,
        not_before=parsed.not_before,
        not_after=parsed.not_after,
        serial=parsed.serial,
        sans=parsed.sans,
        version=parsed.version,
        signature_algorithm=parsed.signature_algorithm,
        key_algorithm=parsed.key_algorithm,
        key_bits=parsed.key_bits,
        sha256_fingerprint=parsed.sha256_fingerprint,
        is_ca=parsed.is_ca,
    )


def attempt(
    host: str,
    port: int,
    timeout: float,
    min_version=None,
    max_version=None,
    ciphers: Optional[str] = None,
    check_hostname: bool = False,
) -> Tuple[bool, object, str]:
    """Try one handshake. Returns (ok, socket_or_None, error_string).

    ``check_hostname`` defaults to False because this helper is used for
    *observation*: finding out what the server offers, including a chain the
    local trust store does not know. Verifying here would make one untrusted
    intermediate collapse the entire report into "unreachable". Verification is
    a single dedicated probe, reported as its own finding.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # PROTOCOL_TLS_CLIENT starts with check_hostname=True, and ssl refuses to let
    # verify_mode become CERT_NONE while that is on. The two settings are
    # mutually exclusive, so they are chosen together rather than sequentially.
    # Setting them in the "obvious" order raised ValueError, every probe failed,
    # and the tool confidently reported healthy hosts as unreachable.
    if check_hostname:
        # Verification probe: a normal client that must succeed.
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        # Observation probe: accept any certificate so a broken chain does not
        # abort the scan. Verification is reported separately as a finding.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if min_version is not None:
        ctx.minimum_version = min_version
    if max_version is not None:
        ctx.maximum_version = max_version
    if ciphers:
        try:
            # set_ciphers returns False when OpenSSL rejects the suite outright
            # (common: NULL/EXP suites are disabled at security level 2). The
            # return value MUST be checked. Ignoring it left the default cipher
            # list in place, the handshake then succeeded with a modern suite,
            # and the tool reported NULL-SHA as "accepted" by the server when in
            # truth it was never even offered.
            if ctx.set_ciphers(ciphers) is False:
                return (
                    False,
                    None,
                    f"cipher suite {ciphers!r} rejected by local OpenSSL",
                )
        except ssl.SSLError as exc:
            return False, None, f"cipher-set rejected locally: {exc}"

    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return False, None, f"connect failed: {exc}"

    try:
        # server_hostname must ALWAYS be sent: it carries SNI. Setting it to None
        # when verification is off sends no SNI at all, and any virtual-hosted
        # server then rejects the handshake with SSLV3_ALERT_HANDSHAKE_FAILURE.
        # That bug made this tool report healthy, popular sites as unreachable.
        # SNI and certificate *verification* are separate concerns; only the
        # latter is controlled by check_hostname.
        wrapped = ctx.wrap_socket(raw, server_hostname=host)
        return True, wrapped, ""
    except (ssl.SSLError, OSError, ValueError) as exc:
        try:
            raw.close()
        except OSError:
            pass
        return False, None, str(exc)


def _close(sock) -> None:
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass


def audit_host(
    host: str,
    port: int = 443,
    timeout: float = 10.0,
    probe_weak_ciphers: bool = True,
    now: Optional[_dt.datetime] = None,
) -> AuditResult:
    """Audit one host:port. Never raises for network or TLS problems."""
    result = AuditResult(host=host, port=port)

    ok, sock, err = attempt(host, port, timeout)
    if not ok or sock is None:
        result.error = err
        result.findings = _evaluate(result, now=now)
        return result

    result.reachable = True
    try:
        raw_cert = sock.getpeercert()
        der = sock.getpeercert(binary_form=True)
        cipher = sock.cipher()
        protocol = sock.version()
    finally:
        _close(sock)

    result.negotiated_protocol = protocol or ""
    if cipher:
        result.negotiated_cipher = cipher[0]
        result.cipher_bits = cipher[2]

    # Prefer the DER parse: it works with verification disabled, which is how
    # every probe in this tool connects. Fall back to the verified-mode dict
    # only if the DER is somehow unavailable.
    parsed = cert_from_der(der) if der else None
    if parsed is not None:
        result.cert = parsed
    elif raw_cert:
        result.cert = cert_from_peercert(raw_cert)

    for name, version in _PROTOCOLS:
        if version is None:
            result.protocols[name] = False
            continue
        supported, probe_sock, _ = attempt(
            host, port, timeout, min_version=version, max_version=version
        )
        result.protocols[name] = supported
        _close(probe_sock)

    if probe_weak_ciphers:
        for suite in _WEAK_CIPHERS:
            accepted, cipher_sock, cipher_err = attempt(
                host,
                port,
                timeout,
                ciphers=suite,
                min_version=ssl.TLSVersion.TLSv1_2,
                # TLS 1.3 suites are not addressable via set_ciphers, so a
                # TLS 1.3 handshake would silently "accept" every legacy suite.
                # Pin the ceiling to 1.2 or the probe measures nothing.
                max_version=ssl.TLSVersion.TLSv1_2,
            )
            _close(cipher_sock)
            # A locally-rejected suite never reached the network; counting it
            # would be a fabricated finding.
            if accepted and "rejected by local OpenSSL" not in cipher_err:
                result.weak_ciphers_accepted.append(suite)

    result.findings = _evaluate(result, now=now)
    return result


def _evaluate(result: "AuditResult", now=None):
    """Thin re-export so callers that imported the old private name keep working."""
    from .findings import evaluate

    return evaluate(result, now=now)
