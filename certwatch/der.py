"""A minimal DER reader for X.509 certificates.

Why this exists: ``ssl.SSLSocket.getpeercert()`` returns an empty dict unless
certificate verification is enabled. Since this tool deliberately scans hosts
whose chains it cannot verify, it cannot use that method and must decode the
DER itself. The stdlib offers no way to do so.

Scope is intentionally narrow: enough of X.509 to answer "who issued this, who
is it for, when does it expire, how big is the key, and what signed it". No
signature verification, no chain building, no policy. Those are what ``ssl``
already does correctly; this module only reports what it refuses to hand over.

Everything here is pure bytes-in/dicts-out, so it is testable without a network
and without a certificate authority.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


class DERError(ValueError):
    """Raised when the input is not decodable as the structure expected."""


_TAG_INTEGER = 0x02
_TAG_BIT_STRING = 0x03
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_BOOLEAN = 0x01
_TAG_UTC_TIME = 0x17
_TAG_GENERALIZED_TIME = 0x18
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31
_TAG_CTX_0 = 0xA0
_TAG_CTX_3 = 0xA3


def _read_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    """Read one tag-length-value at ``offset``.

    Returns (tag, value_bytes, offset_of_next_tlv). Only the definite-length
    forms are accepted, which is all DER permits.
    """
    if offset >= len(data):
        raise DERError(f"unexpected end of data at offset {offset}")

    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise DERError("truncated length field")

    first = data[offset]
    offset += 1

    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DERError("indefinite length is not valid DER")
    else:
        count = first & 0x7F
        if count > 4:
            raise DERError(f"length field of {count} bytes is implausible")
        if offset + count > len(data):
            raise DERError("truncated long-form length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count

    end = offset + length
    if end > len(data):
        raise DERError(f"declared length {length} overruns buffer at offset {offset}")
    return tag, data[offset:end], end


def _children(data: bytes) -> List[Tuple[int, bytes]]:
    """Split a constructed value into its child TLVs."""
    out: List[Tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        tag, value, offset = _read_tlv(data, offset)
        out.append((tag, value))
    return out


def _decode_oid(raw: bytes) -> str:
    """Decode an OBJECT IDENTIFIER into dotted form."""
    if not raw:
        raise DERError("empty OID")
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _decode_integer(raw: bytes) -> int:
    return int.from_bytes(raw, "big", signed=True) if raw else 0


def _decode_time(tag: int, raw: bytes) -> Optional[_dt.datetime]:
    """Decode UTCTime or GeneralizedTime."""
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return None

    if text.endswith("Z"):
        text = text[:-1]

    if tag == _TAG_UTC_TIME:
        # RFC 5280: YY is 20YY when below 50 and 19YY otherwise. A two-digit
        # year taken literally makes a 2049 expiry look like 1949.
        if len(text) < 10:
            return None
        try:
            year_two = int(text[0:2])
            year = 2000 + year_two if year_two < 50 else 1900 + year_two
            second = int(text[10:12]) if len(text) >= 12 else 0
            return _dt.datetime(
                year,
                int(text[2:4]),
                int(text[4:6]),
                int(text[6:8]),
                int(text[8:10]),
                second,
                tzinfo=_dt.timezone.utc,
            )
        except ValueError:
            return None

    if tag == _TAG_GENERALIZED_TIME:
        if len(text) < 10:
            return None
        try:
            minute = int(text[10:12]) if len(text) >= 12 else 0
            second = int(text[12:14]) if len(text) >= 14 else 0
            return _dt.datetime(
                int(text[0:4]),
                int(text[4:6]),
                int(text[6:8]),
                int(text[8:10]),
                minute,
                second,
                tzinfo=_dt.timezone.utc,
            )
        except ValueError:
            return None

    return None


_ATTR_NAMES: Dict[str, str] = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
}

_SIG_ALGS: Dict[str, str] = {
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.3": "md4WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
}

_CURVE_BITS: Dict[str, int] = {
    "1.2.840.10045.3.1.7": 256,  # prime256v1 / P-256
    "1.3.132.0.34": 384,  # secp384r1 / P-384
    "1.3.132.0.35": 521,  # secp521r1 / P-521
    "1.3.132.0.33": 224,  # secp224r1
}


@dataclass
class Name:
    """A distinguished name as an ordered list of (short_attr, value)."""

    parts: List[Tuple[str, str]] = field(default_factory=list)

    def __str__(self) -> str:
        return ", ".join(f"{key}={value}" for key, value in self.parts)

    def get(self, attr: str) -> str:
        for key, value in self.parts:
            if key == attr:
                return value
        return ""


def _parse_name(raw: bytes) -> Name:
    """Parse a Name: SEQUENCE OF SET OF SEQUENCE { OID, value }."""
    name = Name()
    for tag, value in _children(raw):
        if tag != _TAG_SET:
            continue
        for set_tag, atv in _children(value):
            if set_tag != _TAG_SEQUENCE:
                continue
            fields = _children(atv)
            if len(fields) < 2:
                continue
            oid_tag, oid_raw = fields[0]
            if oid_tag != _TAG_OID:
                continue
            oid = _decode_oid(oid_raw)
            _, val_raw = fields[1]
            try:
                text = val_raw.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001 - never fail a scan on a name
                text = val_raw.hex()
            name.parts.append((_ATTR_NAMES.get(oid, oid), text))
    return name


@dataclass
class ParsedCertificate:
    subject: str = ""
    issuer: str = ""
    subject_cn: str = ""
    not_before: Optional[_dt.datetime] = None
    not_after: Optional[_dt.datetime] = None
    serial: str = ""
    sans: List[str] = field(default_factory=list)
    version: int = 0
    signature_algorithm: str = ""
    signature_oid: str = ""
    key_algorithm: str = ""
    key_bits: int = 0
    sha256_fingerprint: str = ""
    is_ca: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "subject_cn": self.subject_cn,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "serial": self.serial,
            "sans": self.sans,
            "version": self.version,
            "signature_algorithm": self.signature_algorithm,
            "key_algorithm": self.key_algorithm,
            "key_bits": self.key_bits,
            "sha256_fingerprint": self.sha256_fingerprint,
            "is_ca": self.is_ca,
        }


def _parse_validity(raw: bytes):
    not_before = not_after = None
    for tag, value in _children(raw):
        if tag in (_TAG_UTC_TIME, _TAG_GENERALIZED_TIME):
            if not_before is None:
                not_before = _decode_time(tag, value)
            else:
                not_after = _decode_time(tag, value)
    return not_before, not_after


def _parse_san(extn_value: bytes) -> List[str]:
    """Decode subjectAltName.

    The extnValue is a GeneralNames, which is a SEQUENCE *wrapping* the
    individual GeneralName entries. Parsing the outer value directly yields one
    child (that SEQUENCE) and no names at all, which silently produced an empty
    SAN list for every certificate. The extensions decoded fine, so this looked
    like the target simply had no SANs.
    """
    out: List[str] = []
    try:
        entries = _children(extn_value)
        if len(entries) == 1 and entries[0][0] == _TAG_SEQUENCE:
            entries = _children(entries[0][1])
    except DERError:
        return out

    for tag, value in entries:
        try:
            if tag == 0x82:  # [2] dNSName
                out.append("DNS:" + value.decode("ascii", "replace"))
            elif tag == 0x81:  # [1] rfc822Name
                out.append("email:" + value.decode("ascii", "replace"))
            elif tag == 0x87:  # [7] iPAddress
                if len(value) == 4:
                    out.append("IP:" + ".".join(str(b) for b in value))
                elif len(value) == 16:
                    groups = [value[i : i + 2].hex() for i in range(0, 16, 2)]
                    out.append("IP:" + ":".join(groups))
                else:
                    out.append("IP:" + value.hex())
            elif tag == 0x86:  # [6] uniformResourceIdentifier
                out.append("URI:" + value.decode("ascii", "replace"))
        except Exception:  # noqa: BLE001 - one bad name must not lose the rest
            continue
    return out


def _parse_extensions(raw: bytes, cert: ParsedCertificate) -> None:
    for tag, value in _children(raw):
        if tag != _TAG_SEQUENCE:
            continue
        fields = _children(value)
        if len(fields) < 2 or fields[0][0] != _TAG_OID:
            continue
        oid = _decode_oid(fields[0][1])
        extn_tag, extn_raw = fields[-1]
        if extn_tag != _TAG_OCTET_STRING:
            continue
        if oid == "2.5.29.17":
            cert.sans = _parse_san(extn_raw)
        elif oid == "2.5.29.19":
            # BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }.
            # A substring search for the same bytes was brittle and could match
            # pathLen instead of the CA flag.
            try:
                inner = _children(extn_raw)
                if inner and inner[0][0] == _TAG_SEQUENCE:
                    for ctag, cval in _children(inner[0][1]):
                        if ctag == _TAG_BOOLEAN:
                            cert.is_ca = bool(cval and cval[0])
                            break
            except DERError:
                pass


def _parse_public_key(raw: bytes, cert: ParsedCertificate) -> None:
    """Read subjectPublicKeyInfo for algorithm and key size."""
    fields = _children(raw)
    if len(fields) < 2:
        return
    alg_tag, alg_raw = fields[0]
    if alg_tag == _TAG_SEQUENCE:
        alg_fields = _children(alg_raw)
        if alg_fields and alg_fields[0][0] == _TAG_OID:
            alg_oid = _decode_oid(alg_fields[0][1])
            if alg_oid.startswith("1.2.840.113549.1.1"):
                cert.key_algorithm = "RSA"
            elif alg_oid.startswith("1.2.840.10045.2.1"):
                cert.key_algorithm = "EC"
            elif alg_oid.startswith("1.3.101.112"):
                cert.key_algorithm = "Ed25519"
                cert.key_bits = 256
            elif alg_oid.startswith("1.3.101.113"):
                cert.key_algorithm = "Ed448"
                cert.key_bits = 456

            if cert.key_algorithm == "EC" and len(alg_fields) > 1:
                param_tag, param_raw = alg_fields[1]
                if param_tag == _TAG_OID:
                    cert.key_bits = _CURVE_BITS.get(_decode_oid(param_raw), 0)

    bits_tag, bits_raw = fields[1]
    if bits_tag == _TAG_BIT_STRING and len(bits_raw) > 1 and cert.key_algorithm == "RSA":
        # BIT STRING body is a leading unused-bits byte, then the DER of the key.
        try:
            _, key_value, _ = _read_tlv(bits_raw[1:], 0)
            inner = _children(key_value)
            if inner and inner[0][0] == _TAG_INTEGER:
                modulus = _decode_integer(inner[0][1])
                cert.key_bits = modulus.bit_length() if modulus else 0
        except DERError:
            pass


def parse_certificate(der: bytes) -> ParsedCertificate:
    """Parse a DER-encoded X.509 certificate into the fields this tool reports.

    Raises DERError if the outer structure is not a Certificate. Partial failure
    inside a field yields an empty field rather than an exception: a scanner that
    gives up on an unusual certificate is worse than one that reports what it
    could read.
    """
    if not der:
        raise DERError("empty certificate")

    cert = ParsedCertificate()
    cert.sha256_fingerprint = hashlib.sha256(der).hexdigest()

    tag, cert_body, _ = _read_tlv(der, 0)
    if tag != _TAG_SEQUENCE:
        raise DERError(f"certificate must be a SEQUENCE, got tag 0x{tag:02X}")

    cert_fields = _children(cert_body)
    if len(cert_fields) < 1 or cert_fields[0][0] != _TAG_SEQUENCE:
        raise DERError("certificate is missing its TBSCertificate")

    if len(cert_fields) >= 2 and cert_fields[1][0] == _TAG_SEQUENCE:
        alg_fields = _children(cert_fields[1][1])
        if alg_fields and alg_fields[0][0] == _TAG_OID:
            cert.signature_oid = _decode_oid(alg_fields[0][1])
            cert.signature_algorithm = _SIG_ALGS.get(
                cert.signature_oid, cert.signature_oid
            )

    tbs_fields = _children(cert_fields[0][1])

    index = 0
    if tbs_fields and tbs_fields[0][0] == _TAG_CTX_0:
        inner = _children(tbs_fields[0][1])
        if inner and inner[0][0] == _TAG_INTEGER:
            cert.version = _decode_integer(inner[0][1]) + 1
        index = 1
    else:
        cert.version = 1

    if index < len(tbs_fields) and tbs_fields[index][0] == _TAG_INTEGER:
        cert.serial = "%X" % _decode_integer(tbs_fields[index][1])
        index += 1

    index += 1  # skip inner AlgorithmIdentifier
    if index < len(tbs_fields) and tbs_fields[index][0] == _TAG_SEQUENCE:
        cert.issuer = str(_parse_name(tbs_fields[index][1]))
        index += 1

    if index < len(tbs_fields) and tbs_fields[index][0] == _TAG_SEQUENCE:
        cert.not_before, cert.not_after = _parse_validity(tbs_fields[index][1])
        index += 1

    if index < len(tbs_fields) and tbs_fields[index][0] == _TAG_SEQUENCE:
        subject = _parse_name(tbs_fields[index][1])
        cert.subject = str(subject)
        cert.subject_cn = subject.get("CN")
        index += 1

    if index < len(tbs_fields) and tbs_fields[index][0] == _TAG_SEQUENCE:
        _parse_public_key(tbs_fields[index][1], cert)
        index += 1

    for tag, value in tbs_fields[index:]:
        if tag == _TAG_CTX_3:
            inner = _children(value)
            if inner and inner[0][0] == _TAG_SEQUENCE:
                _parse_extensions(inner[0][1], cert)
            break

    return cert
