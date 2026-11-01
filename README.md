# certwatch

A TLS and certificate auditor with **zero dependencies** and its own X.509/DER
parser. It answers the four questions you actually have about an endpoint:
what does it present, when does it expire, what will it still negotiate, and
does a normal client accept it.

```
$ certwatch example.com
example.com:443  TLSv1.3  TLS_AES_256_GCM_SHA384
  subject: CN=example.com
  issuer:  C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3
  expires: 2026-12-25 22:56:35+00:00 (54 days)
  protocols: TLSv1.2, TLSv1.3

  [MED ] Certificate chain does not verify against the local trust store
```

*Real output. The MEDIUM rather than HIGH is deliberate - see
[docs/limitations.md](docs/limitations.md). Run against this project's build
container, whose CA bundle is minimal, so the verification failure is about the
scanner's environment and not the target.*

## Why not just use `openssl s_client`

For one host, use `openssl`. This exists for the case where you have forty
hosts, want a severity-ranked answer, and want it to fail a build. It also
reports things `s_client` makes you assemble by hand: whether a client with
the system trust store accepts the endpoint, whether legacy protocol versions
still complete a handshake, and whether any weak cipher suite is negotiable.

## Install

```bash
git clone https://github.com/kkcyber2/certwatch
cd certwatch
python -m pip install -e .
```

Python 3.9+. No dependencies. Works anywhere stdlib `ssl` works.

## Use

```bash
certwatch example.com                  # one host
certwatch example.com:8443             # non-default port
certwatch --file hosts.txt             # one target per line, # comments allowed
certwatch example.com --json           # machine-readable
certwatch example.com --min-severity high --no-colour
certwatch [::1]:443                    # IPv6
```

Exit code is `1` when any finding is `high` or above, so it composes with cron
and CI without parsing output.

## What it checks

| Check | Severity |
|---|---|
| Certificate expired | critical |
| SSLv3 accepted | critical |
| Expires within 14 days | high |
| TLS 1.0 / 1.1 accepted | high |
| Weak cipher suite accepted | high |
| SHA-1 or MD5 signature | high |
| RSA under 2048 / EC under 224 bits | high |
| Hostname mismatch | high |
| Cipher key under 128 bits | high |
| No protocol completed a handshake | high |
| Expires within 30 days | medium |
| Self-signed | medium |
| Chain does not verify locally | medium |
| Host unreachable | info |

## The DER parser

`ssl.SSLSocket.getpeercert()` returns `{}` unless certificate verification is
enabled. This tool deliberately connects with verification off - a chain it
cannot verify is a finding, not a reason to stop talking - so it cannot use
that method. Stdlib offers no alternative, so `certwatch/der.py` decodes the
DER itself: tag-length-value, OIDs, `UTCTime`/`GeneralizedTime` with the
RFC 5280 two-digit-year pivot, `subjectAltName`, `basicConstraints`, and
`subjectPublicKeyInfo` for algorithm and key size.

Scope is deliberately narrow: **it parses, it does not verify signatures or
build chains.** That is what `ssl` already does correctly. This module only
reports what `ssl` refuses to hand over.

## Verification

**69 tests pass** on Python 3.9/3.11/3.12, counted from a fresh clone rather
than the working tree. With networking removed, **65 pass and 4 skip**: the
live-certificate checks skip rather than fail, so a green offline run covers
65 of the 69.

Threshold logic runs offline against a fixed clock, because "expires within 14
days" is exactly the kind of rule that rots silently and a test needing the
internet to check it is a test that gets skipped. Separately, CI asserts
against a live endpoint that the parser produces an issuer and an expiry date,
because no fixture can prove that.

Five bugs that produced confident, wrong output were caught this way, including
a scanner that reported healthy public sites as unreachable and one that
invented cipher findings for suites the local library had rejected. Details:
**[docs/verification.md](docs/verification.md)**.

## Legal and authorised use

Scan only systems you own or are explicitly authorised to test. This tool only
performs TLS handshakes and reads what the server volunteers, but unauthorised
scanning may still be unlawful where you are.

## License

MIT. See [LICENSE](LICENSE).
