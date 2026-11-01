"""DER parsing tests.

Two kinds of test here:

1. Hand-built DER encodings, so primitives (length forms, OIDs, times) are
   pinned without depending on any network or fixture file.
2. A round trip against a real certificate fetched at runtime, skipped when the
   network is unavailable. Hand-built fixtures prove the parser handles what I
   *thought* certificates look like; only a real one proves it handles what they
   actually look like. The SAN bug in this project was invisible to fixtures.
"""

from __future__ import annotations

import datetime as dt

import pytest

from certwatch.der import (
    DERError,
    _decode_oid,
    _decode_time,
    _read_tlv,
    parse_certificate,
)


def tlv(tag: int, value: bytes) -> bytes:
    """Encode one DER TLV with definite length."""
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    length_bytes = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length_bytes)]) + length_bytes + value


class TestTLV:
    def test_short_form(self):
        tag, value, nxt = _read_tlv(tlv(0x02, b"\x01\x02"), 0)
        assert (tag, value, nxt) == (0x02, b"\x01\x02", 4)

    def test_long_form(self):
        payload = b"x" * 300
        tag, value, nxt = _read_tlv(tlv(0x04, payload), 0)
        assert tag == 0x04
        assert value == payload
        assert nxt == len(tlv(0x04, payload))

    def test_boundary_127_short_128_long(self):
        _, v127, _ = _read_tlv(tlv(0x04, b"a" * 127), 0)
        _, v128, _ = _read_tlv(tlv(0x04, b"a" * 128), 0)
        assert len(v127) == 127 and len(v128) == 128

    def test_truncated_header_raises(self):
        with pytest.raises(DERError):
            _read_tlv(b"", 0)
        with pytest.raises(DERError):
            _read_tlv(b"\x30", 0)

    def test_length_overrun_raises(self):
        """A declared length longer than the buffer must be an error.

        Without this check the parser happily slices past the end and returns a
        short value, which then desynchronises every subsequent field.
        """
        with pytest.raises(DERError, match="overruns|truncated"):
            _read_tlv(b"\x04\x10short", 0)

    def test_indefinite_length_rejected(self):
        """Indefinite length is BER, not DER."""
        with pytest.raises(DERError, match="indefinite"):
            _read_tlv(b"\x30\x80\x00\x00", 0)


class TestOID:
    def test_rsa_encryption_oid(self):
        # 1.2.840.113549.1.1.11
        raw = bytes.fromhex("2a864886f70d01010b")
        assert _decode_oid(raw) == "1.2.840.113549.1.1.11"

    def test_common_name_oid(self):
        assert _decode_oid(bytes.fromhex("550403")) == "2.5.4.3"

    def test_multibyte_arc(self):
        """Arcs above 127 use continuation bytes; a naive parse breaks here."""
        raw = bytes.fromhex("2a8648ce3d030107")  # 1.2.840.10045.3.1.7
        assert _decode_oid(raw) == "1.2.840.10045.3.1.7"

    def test_empty_raises(self):
        with pytest.raises(DERError):
            _decode_oid(b"")


class TestTime:
    def test_utctime(self):
        parsed = _decode_time(0x17, b"261225225635Z")
        assert parsed == dt.datetime(2026, 12, 25, 22, 56, 35, tzinfo=dt.timezone.utc)

    def test_utctime_pivot_before_2050(self):
        """RFC 5280: YY < 50 means 20YY, so '49' is 2049, not 1949."""
        parsed = _decode_time(0x17, b"491225000000Z")
        assert parsed is not None
        assert parsed.year == 2049

    def test_utctime_pivot_after_2050(self):
        parsed = _decode_time(0x17, b"501225000000Z")
        assert parsed is not None
        assert parsed.year == 1950

    def test_generalized_time(self):
        parsed = _decode_time(0x18, b"20261225225635Z")
        assert parsed is not None
        assert parsed.year == 2026

    def test_garbage_returns_none(self):
        assert _decode_time(0x17, b"nonsense") is None
        assert _decode_time(0x18, b"xx") is None

    def test_results_are_utc_aware(self):
        parsed = _decode_time(0x17, b"261225225635Z")
        assert parsed is not None
        assert parsed.utcoffset() == dt.timedelta(0)


class TestParseCertificate:
    def test_empty_raises(self):
        with pytest.raises(DERError):
            parse_certificate(b"")

    def test_non_sequence_rejected(self):
        with pytest.raises(DERError, match="SEQUENCE"):
            parse_certificate(tlv(0x02, b"\x01"))

    def test_missing_tbs_rejected(self):
        with pytest.raises(DERError, match="TBSCertificate"):
            parse_certificate(tlv(0x30, b""))

    def test_fingerprint_is_sha256_of_input(self):
        import hashlib

        der = tlv(0x30, tlv(0x30, b""))
        try:
            cert = parse_certificate(der)
        except DERError:
            pytest.skip("minimal certificate does not parse")
        assert cert.sha256_fingerprint == hashlib.sha256(der).hexdigest()


class TestRealCertificate:
    """Round trip against a live certificate.

    Skipped rather than failed when there is no network, so the suite stays
    honest on an offline machine instead of going red for the wrong reason.
    """

    @staticmethod
    def _fetch(host: str = "example.com") -> bytes:
        import socket
        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            raw = socket.create_connection((host, 443), timeout=15)
            sock = ctx.wrap_socket(raw, server_hostname=host)
        except OSError as exc:  # pragma: no cover - network dependent
            pytest.skip(f"network unavailable: {exc}")
        try:
            return sock.getpeercert(binary_form=True)
        finally:
            sock.close()

    def test_parses_a_real_certificate(self):
        cert = parse_certificate(self._fetch())

        # These assertions all failed at some point during development, which is
        # why each one is here rather than just "it returns something".
        assert cert.subject.startswith("CN=")
        assert cert.issuer
        assert cert.version == 3
        assert cert.not_before is not None
        assert cert.not_after is not None
        assert cert.not_after > cert.not_before
        assert cert.key_algorithm in ("RSA", "EC", "Ed25519", "Ed448")
        assert cert.key_bits >= 2048 or (cert.key_algorithm == "EC" and cert.key_bits >= 256)
        assert cert.sha256_fingerprint
        assert len(cert.sha256_fingerprint) == 64

    def test_sans_are_extracted(self):
        """Pins the nested-SEQUENCE bug.

        subjectAltName is a SEQUENCE *wrapping* the GeneralName entries. Reading
        the outer value directly returned one child and zero names, on every
        certificate, with no error anywhere.
        """
        cert = parse_certificate(self._fetch())
        assert cert.sans, "no SANs parsed; public certificates always have them"
        assert all(":" in san for san in cert.sans)
        assert any(san.startswith("DNS:") for san in cert.sans)

    def test_public_certificate_is_not_a_ca(self):
        cert = parse_certificate(self._fetch())
        assert cert.is_ca is False

    def test_signature_algorithm_is_named(self):
        cert = parse_certificate(self._fetch())
        assert cert.signature_algorithm
        # Should have been mapped from an OID, not left as a dotted number.
        assert cert.signature_algorithm != cert.signature_oid or cert.signature_oid == ""
