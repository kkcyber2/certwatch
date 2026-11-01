# Verification record

What was run and what was not tested.

## Test suites

The suite is split in two: one file covers the reporting rules, the other the
structure parser. The expiry thresholds are evaluated against a fixed clock
rather than the system clock, so a rule like "expires within 14 days" cannot
start failing a year from now for no reason.

The CI matrix covers Python 3.9, 3.11 and 3.12. One CI step also scans a live
endpoint and requires the expiry field to be present, because a fixture cannot
prove the parser handles a certificate issued by a real authority.

## Problems found by running it, not by reading it

Each of these produced plausible, confident output that was wrong. That is the
failure mode this project is about.

### 1. Server name indication omitted

The hostname reached the TLS wrapper only when verification was on. With
verification off, the normal path, the server had no way to select a
certificate, the connection was refused, and the tool reported healthy public
sites as down.

Server name indication and verification are independent. Fixed by always
passing the hostname.

### 2. Context settings applied in the wrong order

The client context starts with hostname checking on, and the library refuses to
accept a verify mode of none while it is. Setting them sequentially raised on
every connection. The two are mutually exclusive, so they are now chosen
together.

### 3. Cipher probe ignored its own failure signal

The cipher-setting call returns false when the local library will not accept a
suite. That return value was ignored, the default list stayed in place, the
handshake succeeded with a modern suite, and the tool reported a legacy
algorithm as accepted by the server when it had never been offered. The probe
ceiling is also pinned to the older protocol version, because the newer one
does not route through that call and would make every probe pass.

### 4. Severity ordered by alphabet, inverting every comparison

The severity type subclasses str. Defining only two comparison operators leaves
the other two falling through to string comparison, where "critical" sorts
before "medium". Every greater-than check on severity was silently backwards.
All four operators are now explicit, and three tests pin it.

### 5. Subject alternative names needed a nested unwrap

The extension value is a sequence wrapping the individual names. Reading the
outer value yielded one child and no names, on every certificate, with no
error. Extensions decoded fine, so it looked like the target simply had none.
Caught only by asserting on a real certificate; no fixture exposed it.

Also: the certificate accessor used here returns an empty mapping when
verification is off, so the first version omitted the expiry date entirely.
That is the field the tool exists to report. Parsing the structure directly
closed it.

## A change made because a finding was misleading

The chain-trust finding was originally high. Verification runs against the
scanner's trust store, so behind an intercepting proxy or in a minimal
container image every external site fails and the finding says nothing about
the target. Downgraded to medium with the dependence stated in the finding
text. A tool that raises false alarms on its own environment teaches operators
to ignore it.

The same reasoning removed invented network findings: a suite rejected locally
is no longer counted as accepted by the server.

## Not verified

Stated plainly rather than implied by silence:

- No signature verification or chain building. The parser reads fields; it does
  not confirm the signature is valid or that the chain terminates in a trusted
  root.
- No revocation checking. A revoked but unexpired certificate passes.
- Only endpoints reachable from this environment were tested. Client
  certificate authentication, hostname override, the upgrade handshakes on mail
  and directory protocols, and non-443 services are all untested. `--port`
  exists but no non-443 target was exercised.
- The weak-cipher list depends on the local library build. Suites rejected
  locally are correctly skipped, so a scan on one machine can report fewer
  accepted suites than another.
- The live-certificate tests skip without network, so the suite stays green
  offline. The headline count is a claim about a machine with connectivity.
