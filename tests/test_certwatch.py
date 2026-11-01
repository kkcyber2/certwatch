"""Tests for the pure parts of certwatch.

The network path is exercised by the CI smoke step against a live endpoint;
everything here runs offline with a fixed clock. That split is deliberate:
thresholds like "expires within 14 days" are exactly the kind of logic that
rots silently, and a test that has to reach the internet to check them is a
test that will be skipped.
"""

from __future__ import annotations

import datetime as _dt
import os
import socket
import ssl
import sys

import pytest

from certwatch.audit import (
    AuditResult,
    CertInfo,
    Finding,
    Severity,
    attempt,
    audit_host,
    cert_from_peercert,
    format_name,
    parse_cert_time,
)
from certwatch.cli import parse_target
from certwatch.findings import evaluate

UTC = _dt.timezone.utc
FIXED_NOW = _dt.datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)


def days_from_now(n: int) -> _dt.datetime:
    return FIXED_NOW + _dt.timedelta(days=n)


def cert(**kwargs) -> CertInfo:
    base = dict(
        subject="CN=example.com",
        issuer="C=US, O=Test CA, CN=Test Intermediate",
        not_before=days_from_now(-365),
        not_after=days_from_now(200),
        key_algorithm="RSA",
        key_bits=2048,
        signature_algorithm="sha256WithRSAEncryption",
    )
    base.update(kwargs)
    return CertInfo(**base)


def result(**kwargs) -> AuditResult:
    base = dict(host="example.com", port=443, reachable=True)
    base.update(kwargs)
    return AuditResult(**base)


def ids(findings):
    return {f.id for f in findings}


class TestSeverityOrdering:
    def test_rank_order(self):
        assert Severity.INFO < Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    def test_greater_than_uses_rank_not_text(self):
        """critical must exceed low; alphabetically 'critical' < 'low'.

        Severity subclasses str, so without an explicit __gt__ the comparison
        silently falls through to string ordering and every `>` check is wrong.
        """
        assert Severity.CRITICAL > Severity.LOW
        assert Severity.HIGH > Severity.INFO
        assert not (Severity.LOW > Severity.CRITICAL)

    def test_greater_equal(self):
        assert Severity.HIGH >= Severity.HIGH
        assert Severity.CRITICAL >= Severity.LOW
        assert not (Severity.LOW >= Severity.HIGH)

    def test_rank_values_are_distinct(self):
        ranks = [s.rank for s in Severity]
        assert len(ranks) == len(set(ranks))


class TestParseTarget:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("example.com", ("example.com", 443)),
            ("example.com:8443", ("example.com", 8443)),
            ("https://example.com/path", ("example.com", 443)),
            ("https://example.com:9443/x", ("example.com", 9443)),
            ("  spaced.example  ", ("spaced.example", 443)),
            ("[::1]:8443", ("::1", 8443)),
            ("[::1]", ("::1", 443)),
            ("::1", ("::1", 443)),
        ],
    )
    def test_valid(self, text, expected):
        assert parse_target(text) == expected

    @pytest.mark.parametrize("text", ["", "   "])
    def test_empty_rejected(self, text):
        with pytest.raises(ValueError):
            parse_target(text)

    def test_bad_port_rejected(self):
        with pytest.raises(ValueError, match="bad port"):
            parse_target("example.com:notaport")

    def test_unterminated_v6_rejected(self):
        with pytest.raises(ValueError, match="unterminated"):
            parse_target("[::1")


class TestCertTime:
    def test_space_padded_day(self):
        """OpenSSL pads single-digit days; a strict parse loses the expiry."""
        parsed = parse_cert_time("Jun  1 12:00:00 2027 GMT")
        assert parsed is not None
        assert parsed.year == 2027
        assert parsed.month == 6
        assert parsed.day == 1

    def test_two_digit_day(self):
        parsed = parse_cert_time("Dec 25 23:59:59 2026 GMT")
        assert parsed == _dt.datetime(2026, 12, 25, 23, 59, 59, tzinfo=UTC)

    def test_without_zone_suffix(self):
        parsed = parse_cert_time("Dec 25 23:59:59 2026")
        assert parsed is not None
        assert parsed.tzinfo is UTC

    def test_garbage_returns_none(self):
        assert parse_cert_time("not a date") is None
        assert parse_cert_time("") is None


class TestCertInfo:
    def test_days_remaining_is_integer(self):
        info = cert(not_after=_dt.datetime.now(UTC) + _dt.timedelta(days=10, hours=1))
        assert info.days_remaining == 10

    def test_days_remaining_none_without_expiry(self):
        assert cert(not_after=None).days_remaining is None

    def test_to_dict_roundtrips_dates_as_iso(self):
        payload = cert().to_dict()
        assert payload["not_after"].endswith("+00:00")
        assert payload["key_bits"] == 2048


class TestAuditResult:
    def test_highest_severity(self):
        res = result(
            findings=[
                Finding("a", "A", Severity.LOW, ""),
                Finding("b", "B", Severity.CRITICAL, ""),
                Finding("c", "C", Severity.MEDIUM, ""),
            ]
        )
        assert res.highest_severity is Severity.CRITICAL

    def test_highest_severity_empty(self):
        assert result().highest_severity is None

    def test_to_dict_includes_findings(self):
        res = result(findings=[Finding("x", "X", Severity.HIGH, "d", "r")])
        payload = res.to_dict()
        assert payload["findings"][0]["severity"] == "high"
        assert payload["highest_severity"] == "high"


class TestEvaluation:
    def test_clean_certificate_reports_nothing(self, monkeypatch):
        monkeypatch.setattr(
            "certwatch.findings.attempt", lambda *a, **k: (True, None, "")
        )
        assert evaluate(result(cert=cert()), now=FIXED_NOW) == []

    def test_expired(self, monkeypatch):
        monkeypatch.setattr(
            "certwatch.findings.attempt", lambda *a, **k: (True, None, "")
        )
        findings = evaluate(
            result(cert=cert(not_after=days_from_now(-3))), now=FIXED_NOW
        )
        assert "cert-expired" in ids(findings)
        assert next(f for f in findings if f.id == "cert-expired").severity is Severity.CRITICAL

    def test_expiring_within_14_days_is_high(self, monkeypatch):
        monkeypatch.setattr(
            "certwatch.findings.attempt", lambda *a, **k: (True, None, "")
        )
        findings = evaluate(
            result(cert=cert(not_after=days_from_now(9))), now=FIXED_NOW
        )
        assert "cert-expiring" in ids(findings)

    def test_expiring_within_30_days_is_medium(self, monkeypatch):
        monkeypatch.setattr(
            "certwatch.findings.attempt", lambda *a, **k: (True, None, "")
        )
        findings = evaluate(
            result(cert=cert(not_after=days_from_now(21))), now=FIXED_NOW
        )
        assert "cert-expiring-soon" in ids(findings)
        assert "cert-expiring" not in ids(findings)

    def test_beyond_30_days_is_quiet(self, monkeypatch):
        monkeypatch.setattr(
            "certwatch.findings.attempt", lambda *a, **k: (True, None, "")
        )
        findings = evaluate(
            result(cert=cert(not_after=days_from_now(31))), now=FIXED_NOW
        )
        assert not any(f.id.startswith("cert-expir") for f in findings)

    def test_sslv3_accepted_is_critical(self, monkeypatch):
        monkeypatch.setattr(
            "certwatch.findings.attempt", lambda *a, **k: (True, None, "")
        )
        findings = evaluate(
            result(cert=cert(), protocols={"SSLv3": True, "TLSv1.2": True}),
            now=FIXED_NOW,
        )
        ssl_finding = next(f for f in findings if f.id == "ssl-v3")
        assert ssl_finding.severity is Severity.CRITICAL

    def test_tls10_is_high(self, monkeypatch):
        monkeypatch.setattr(
            "certwatch.findings.attempt", lambda *a, **k: (True, None, "")
        )
        findings = evaluate(
            result(cert=cert(), protocols={"TLSv1": True}), now=FIXED_NOW
        )
        assert "protocol-tlsv1" in ids(findings)

    def test_all_protocols_failing_is_reported(self, monkeypatch):
        monkeypatch.setattr(
            "certwatch.findings.attempt", lambda *a, **k: (True, None, "")
        )
        findings = evaluate(
            result(cert=cert(), protocols={"TLSv1.2": False, "TLSv1.3": False}),
            now=FIXED_NOW,
        )
        assert "no-protocol" in ids(findings)

    def test_weak_ciphers(self, monkeypatch):
        monkeypatch.setattr(
            "certwatch.findings.attempt", lambda *a, **k: (True, None, "")
        )
        findings = evaluate(
            result(cert=cert(), weak_ciphers_accepted=["RC4-SHA"]), now=FIXED_NOW
        )
        assert "weak-ciphers" in ids(findings)

    def test_self_signed(self, monkeypatch):
        monkeypatch.setattr(
            "certwatch.findings.attempt", lambda *a, **k: (True, None, "")
        )
        findings = evaluate(
            result(cert=cert(subject="CN=x", issuer="CN=x")), now=FIXED_NOW
        )
        assert "self-signed" in ids(findings)

    def test_sha1_signature(self, monkeypatch):
        monkeypatch.setattr(
            "certwatch.findings.attempt", lambda *a, **k: (True, None, "")
        )
        findings = evaluate(
            result(cert=cert(signature_algorithm="sha1WithRSAEncryption")),
            now=FIXED_NOW,
        )
        assert "weak-signature" in ids(findings)

    def test_small_rsa_key(self, monkeypatch):
        monkeypatch.setattr(
            "certwatch.findings.attempt", lambda *a, **k: (True, None, "")
        )
        findings = evaluate(result(cert=cert(key_bits=1024)), now=FIXED_NOW)
        assert "weak-key" in ids(findings)

    def test_2048_rsa_is_fine(self, monkeypatch):
        monkeypatch.setattr(
            "certwatch.findings.attempt", lambda *a, **k: (True, None, "")
        )
        findings = evaluate(result(cert=cert(key_bits=2048)), now=FIXED_NOW)
        assert "weak-key" not in ids(findings)

    def test_untrusted_chain_is_medium_not_high(self, monkeypatch):
        """Verification depends on the scanner's CA bundle, not the target."""
        monkeypatch.setattr(
            "certwatch.findings.attempt",
            lambda *a, **k: (False, None, "CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate"),
        )
        findings = evaluate(result(cert=cert()), now=FIXED_NOW)
        chain = next(f for f in findings if f.id == "chain-untrusted")
        assert chain.severity is Severity.MEDIUM

    def test_unreachable_only_when_there_is_an_error(self):
        findings = evaluate(result(error="connect failed: timeout"), now=FIXED_NOW)
        assert ids(findings) == {"unreachable"}

    def test_synthetic_result_without_error_is_not_unreachable(self):
        """A test built from a bare AuditResult must not report 'unreachable'.

        Keying the unreachable finding off `not reachable` made every unit test
        below look like it was testing connectivity.
        """
        assert "unreachable" not in ids(evaluate(result(), now=FIXED_NOW))


class TestSeverityFiltering:
    def test_min_severity_filters(self):
        findings = [
            Finding("a", "A", Severity.INFO, ""),
            Finding("b", "B", Severity.HIGH, ""),
        ]
        kept = [f for f in findings if f.severity.rank >= Severity.MEDIUM.rank]
        assert [f.id for f in kept] == ["b"]


class TestNetworkSafety:
    def test_attempt_to_closed_port_returns_error_not_raise(self):
        try:
            probe = socket.socket()
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
            probe.close()
        except OSError:
            pytest.skip("cannot bind a local port in this environment")

        ok, sock, err = attempt("127.0.0.1", port, 1.0)
        assert ok is False
        assert sock is None
        assert "connect failed" in err

    def test_audit_host_never_raises_on_bad_host(self):
        res = audit_host("127.0.0.1", 1, timeout=1.0, probe_weak_ciphers=False)
        assert res.reachable is False
        assert res.error
        assert "unreachable" in ids(res.findings)
