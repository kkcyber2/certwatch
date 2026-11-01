"""Finding derivation: observations in, findings out.

Split from ``audit.py`` so the decision logic can be read, and tested, on its
own. Every function here that matters is pure: given the same AuditResult and
the same clock it returns the same findings, which is what makes the expiry
thresholds testable without waiting three months for a certificate to rot.
"""

from __future__ import annotations

import datetime as _dt
from typing import List, Optional

from .audit import AuditResult, CertInfo, Finding, Severity, _close, attempt


def evaluate(result: AuditResult, now: Optional[_dt.datetime] = None) -> List[Finding]:
    """Turn observations into findings. Pure, so it is testable with a fixed clock."""
    findings: List[Finding] = []

    # A caller testing the evaluator passes a synthetic result with no error; a
    # real failed connection always carries one. Only the latter is a finding.
    # Keying off `not reachable` alone would make every unit test that builds a
    # bare AuditResult report "unreachable" instead of what it was testing.
    if result.error:
        findings.append(
            Finding(
                "unreachable",
                "Host did not complete a TLS handshake",
                Severity.INFO,
                result.error,
                "Confirm the host, port and any firewall between you and it.",
            )
        )
        return findings

    if result.protocols.get("SSLv3"):
        findings.append(
            Finding(
                "ssl-v3",
                "SSLv3 is accepted",
                Severity.CRITICAL,
                "The server completes an SSLv3 handshake. SSLv3 is broken by POODLE "
                "and must not be negotiable.",
                "Disable SSLv3 on the listener.",
            )
        )

    for legacy in ("TLSv1", "TLSv1.1"):
        if result.protocols.get(legacy):
            findings.append(
                Finding(
                    f"protocol-{legacy.lower().replace('.', '_')}",
                    f"{legacy} is accepted",
                    Severity.HIGH,
                    f"The server completes a {legacy} handshake. {legacy} is "
                    "deprecated by RFC 8996.",
                    "Require TLS 1.2 or later.",
                )
            )

    if result.protocols and not any(result.protocols.values()):
        findings.append(
            Finding(
                "no-protocol",
                "No TLS version completed a handshake",
                Severity.HIGH,
                "Every per-version probe failed although a default handshake "
                "succeeded. A middlebox may be rewriting the connection.",
                "Confirm whether a proxy terminates TLS in front of this endpoint.",
            )
        )

    if result.weak_ciphers_accepted:
        findings.append(
            Finding(
                "weak-ciphers",
                "Weak cipher suites accepted",
                Severity.HIGH,
                "Accepted: " + ", ".join(result.weak_ciphers_accepted),
                "Remove RC4, 3DES, NULL and anonymous-DH suites from the cipher list.",
            )
        )

    cert = result.cert
    reference = now or _dt.datetime.now(_dt.timezone.utc)
    if cert is not None:
        if cert.not_after is not None:
            days = int((cert.not_after - reference).total_seconds() // 86400)
            if days < 0:
                findings.append(
                    Finding(
                        "cert-expired",
                        "Certificate has expired",
                        Severity.CRITICAL,
                        f"Expired {abs(days)} day(s) ago on "
                        f"{cert.not_after.date().isoformat()}.",
                        "Renew immediately.",
                    )
                )
            elif days <= 14:
                findings.append(
                    Finding(
                        "cert-expiring",
                        "Certificate expires within 14 days",
                        Severity.HIGH,
                        f"{days} day(s) remaining "
                        f"({cert.not_after.date().isoformat()}).",
                        "Renew now; automated renewal appears to be failing.",
                    )
                )
            elif days <= 30:
                findings.append(
                    Finding(
                        "cert-expiring-soon",
                        "Certificate expires within 30 days",
                        Severity.MEDIUM,
                        f"{days} day(s) remaining "
                        f"({cert.not_after.date().isoformat()}).",
                        "Check that automated renewal is scheduled.",
                    )
                )

        if cert.issuer and cert.subject and cert.issuer == cert.subject:
            findings.append(
                Finding(
                    "self-signed",
                    "Certificate is self-signed",
                    Severity.MEDIUM,
                    "Issuer and subject are identical, so no third party vouches for "
                    "this key. Clients without the CA installed cannot verify it.",
                    "Use a publicly trusted or internally managed CA.",
                )
            )

        sig = cert.signature_algorithm.lower()
        if "md5" in sig or "sha1" in sig:
            findings.append(
                Finding(
                    "weak-signature",
                    "Certificate signed with a weak algorithm",
                    Severity.HIGH,
                    f"signatureAlgorithm is {cert.signature_algorithm!r}.",
                    "Reissue with SHA-256 or better.",
                )
            )

        # Key size is only knowable from the DER parse; getpeercert omits it.
        if cert.key_bits:
            too_small = (cert.key_algorithm == "RSA" and cert.key_bits < 2048) or (
                cert.key_algorithm == "EC" and cert.key_bits < 224
            )
            if too_small:
                findings.append(
                    Finding(
                        "weak-key",
                        f"{cert.key_algorithm} key is too small",
                        Severity.HIGH,
                        f"{cert.key_bits}-bit {cert.key_algorithm} key. NIST and CA/B "
                        "requirements make this unacceptable for a public endpoint.",
                        "Reissue with RSA-2048 or better, or EC P-256.",
                    )
                )

    # Verification is a separate question from "the server speaks TLS": a client
    # that trusts this endpoint must succeed here, so it is checked explicitly.
    verifies, verify_sock, verify_err = attempt(
        result.host, result.port, 10.0, check_hostname=True
    )
    _close(verify_sock)
    if not verifies:
        if "CERTIFICATE_VERIFY_FAILED" in verify_err:
            # Deliberately MEDIUM, not HIGH. Verification runs against THIS
            # host's trust store. Behind an intercepting proxy, or with a
            # non-standard CA bundle, every external certificate fails and the
            # finding is an artefact of the scanner, not of the target.
            # Reporting that at HIGH trains operators to ignore the tool.
            findings.append(
                Finding(
                    "chain-untrusted",
                    "Certificate chain does not verify against the local trust store",
                    Severity.MEDIUM,
                    f"Verification failed: {verify_err}. This result depends on the "
                    "CA bundle of the host doing the scanning: an intercepting proxy "
                    "or a minimal container image will produce this for every "
                    "external site. Confirm from a host with a standard trust store "
                    "before treating it as a defect in the target.",
                    "Serve the full intermediate chain; confirm the leaf matches the "
                    "hostname; re-test from a machine with a stock CA bundle.",
                )
            )
        elif "Hostname mismatch" in verify_err or "hostname" in verify_err.lower():
            findings.append(
                Finding(
                    "hostname-mismatch",
                    "Certificate does not match the hostname",
                    Severity.HIGH,
                    verify_err or "Server hostname did not match the certificate.",
                    "Reissue with the correct subjectAltName entries.",
                )
            )

    if result.cipher_bits and result.cipher_bits < 128:
        findings.append(
            Finding(
                "short-key",
                "Negotiated cipher uses a short key",
                Severity.HIGH,
                f"{result.negotiated_cipher} negotiated at {result.cipher_bits} bits.",
                "Require AEAD suites with at least 128-bit keys.",
            )
        )

    return findings
