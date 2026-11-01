# certwatch

A TLS and certificate auditor with **zero dependencies** and its own X.509 DER
parser. It reports what an endpoint presents, when it expires, which protocol
versions it will still negotiate, and whether a normal client accepts it.

```
$ certwatch example.com
example.com:443  TLSv1.3  TLS_AES_256_GCM_SHA384
  subject: CN=example.com
  issuer:  C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3
  expires: 2026-12-25 22:56:35+00:00 (54 days)
  protocols: TLSv1.2, TLSv1.3

  [MED ] Chain does not verify against the local trust store
```

Real output from this project's build container. MEDIUM rather than HIGH is
deliberate: verification uses the scanner's CA bundle, and a minimal container
fails every external site. See [docs/limitations.md](docs/limitations.md).

## Install and use

```bash
git clone https://github.com/kkcyber2/certwatch
cd certwatch && python -m pip install -e .
```

Python 3.9+, no dependencies.

```bash
certwatch example.com                  # one host
certwatch example.com:8443             # non-default port
certwatch --file hosts.txt             # one per line, # comments allowed
certwatch example.com --json           # machine-readable
certwatch [::1]:443                    # IPv6
```

Exit code is `1` when any finding is `high` or above, so it composes with cron
and CI without parsing output.

## Why there is a DER parser

`getpeercert()` returns an empty dict unless verification is enabled. This tool
connects with verification off, because an untrusted chain is a finding rather
than a reason to stop, so it cannot use that method and stdlib offers no
alternative. `certwatch/der.py` decodes the DER itself: tag-length-value, OIDs,
UTC and generalized time with the RFC 5280 two-digit-year pivot, subject
alternative names, basic constraints, and the public key block for algorithm
and key size.

Scope is narrow: **it parses; it does not verify signatures or build chains.**
That is what `ssl` does correctly, in one dedicated probe.

## Verification

61 tests pass on Python 3.9, 3.11 and 3.12. Threshold logic runs offline
against a fixed clock; a live-endpoint CI step separately proves the parser
yields a real issuer and expiry date.

Full record, including an explicit list of what is not covered:
[docs/verification.md](docs/verification.md).
