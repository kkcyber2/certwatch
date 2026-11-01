# Verification record

What was actually run, what it found, and what was **not** tested. Written
because a test count on its own proves very little.

## Test suites

```
$ python -m pytest
69 passed

$ unshare -n -r python -m pytest     # networking removed
65 passed, 4 skipped
```

| File | Tests | What it pins |
|---|---|---|
| `tests/test_certwatch.py` | 45 | severity ordering, target parsing, cert timestamps, expiry thresholds at 14 and 30 days, protocol and cipher findings, key-size rules |
| `tests/test_der.py` | 24 | TLV length forms, OID arcs, UTC time year pivot, plus a live-certificate round trip |

Both counts were taken from a **fresh clone** with `pip install -e .`, not from
the working tree. The 4 that skip offline are the live-certificate round trips.
A test that needs the internet to check a threshold is a test that gets
skipped, so no threshold this project depends on is in that group.

The expiry thresholds run against a **fixed clock** (`FIXED_NOW`), not
`datetime.now()`. A threshold test that reads the real clock passes today and
fails in a year for no reason.

CI matrix is Python 3.9, 3.11, 3.12. One CI step additionally scans a live
endpoint and asserts `cert.not_after` is populated - a fixture cannot prove the
DER parser handles a real certificate from a real CA.

## Bugs found by running it, not by reading it

Every one of these produced *confident, plausible output that was wrong*. That
is the failure mode this project is about.

### 1. SNI omitted, so every virtual-hosted site reported unreachable

`wrap_socket(server_hostname=None)` sends no SNI. `server_hostname` was set to
the host only when verification was on. With verification off, the normal path,
no SNI went out, the server rejected the handshake with a handshake failure
alert, and the tool reported healthy public sites as down.

SNI and certificate verification are independent. Fixed by always passing
`server_hostname=host`.

### 2. `verify_mode` set after `check_hostname`, raising on every probe

`PROTOCOL_TLS_CLIENT` starts with `check_hostname=True`; `ssl` refuses to let
`verify_mode` become `CERT_NONE` while it is on. Setting them sequentially
raised on every connection. The two settings are mutually exclusive, so they
are now chosen together.

### 3. `set_ciphers` return value ignored, fabricating cipher findings

`set_ciphers` returns `False` when OpenSSL rejects a suite (NULL and export
suites are disabled at security level 2). The return value was ignored, the
default cipher list stayed in place, the handshake succeeded with a *modern*
suite, and the tool reported a legacy suite as "accepted by the server" when it
had never been offered. The probe ceiling is also pinned to TLS 1.2, because
TLS 1.3 suites are not addressable via `set_ciphers` and would make every probe
pass.

### 4. `Severity` ordered by alphabet, inverting every comparison

`Severity` subclasses `str`. Defining only `__lt__`/`__le__` leaves `__gt__`
and `__ge__` falling through to string comparison, where `"critical"` sorts
before `"medium"`. Any `>` check on severity was silently backwards. All four
operators are now explicit, and three tests pin it.

### 5. `subjectAltName` needs a nested-SEQUENCE unwrap, returning none

The extnValue is a `GeneralNames` SEQUENCE *wrapping* the entries. Parsing the
outer value yielded one child and no names, on every certificate, with no
error. Extensions decoded fine, so it looked like the target simply had no
SANs. Caught only by asserting on a real certificate; no fixture exposed it.

Also: `getpeercert()` returns `{}` when verification is off, so the first
version omitted the expiry date entirely. That is the field the tool exists to
report. Parsing the DER closed it.

## A change made because a finding was misleading

`chain-untrusted` was originally **HIGH**. Verification runs against the
scanner's trust store, so behind an intercepting proxy or in a minimal
container image, every external site fails and the finding says nothing about
the target. Downgraded to **MEDIUM** with the dependence stated in the finding
text. A tool that cries wolf on its own environment teaches operators to
ignore it.

The same reasoning removed fabricated network findings: a cipher suite rejected
locally is no longer counted as accepted by the server.

## Not verified

Stated plainly rather than implied by silence:

- **No signature verification or chain building.** The parser reads fields; it
  does not confirm the signature is valid or that the chain terminates in a
  trusted root. That is what `ssl` does, and it is done in exactly one probe.
- **OCSP and CRL checking are not performed.** Revocation is not tested. A
  revoked-but-unexpired certificate will pass.
- **Only tested against endpoints reachable from this environment.** Client
  certificate authentication, SNI with an explicit override, STARTTLS on mail
  and directory protocols, and non-443 services are all untested. `--port`
  exists but no non-443 target was exercised.
- **The weak-cipher probe list is OpenSSL-version dependent.** Which suites are
  locally available (and therefore testable) varies by build. Suites rejected
  locally are correctly skipped, which means a scan on one machine can report
  fewer accepted suites than another.
- **The live-certificate tests skip without network.** On an offline machine
  you get 65 passed and 4 skipped, not 69 passed. That is intentional, but it
  means "69 passed" is a claim about a machine with connectivity.
