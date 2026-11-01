# What this tool cannot see

Kept separate from the README so it does not read as boilerplate. These are
structural limits of the approach, not a backlog.

## Trust-store dependence

The `chain-untrusted` finding is about **the machine running the scan**, not
only the target. Verification uses the scanner's CA bundle. In a container
image with a minimal bundle, or behind an intercepting TLS proxy, every external
endpoint fails and this finding is an artefact of the environment.

This is why it is MEDIUM and why the finding text says so explicitly. Before
treating it as a defect in the target, re-run from a host with a stock trust
store.

## No revocation checking

OCSP and CRL are not consulted. A certificate that has been revoked but has not
yet expired will pass this tool cleanly. If revocation status matters for your
decision, and for a compromised key it does, this tool cannot answer that
question. Use `openssl ocsp` or the issuing authority's own tooling.

## No signature verification, no chain building

`der.py` reads fields out of the certificate. It does not check the signature
over the signed body, and it does not walk a chain to a root. That work is left
to `ssl`, which does it correctly and is used for exactly one dedicated probe.

A consequence worth stating: a certificate carrying a forged issuer field will
have that forged issuer printed. The issuer shown is what the certificate
claims, not a fact established by cryptography.

## Only what the handshake volunteers

This is a network observer, not a scanner-in-depth. It cannot see:

- Cipher suites the server declines to negotiate in a full handshake. TLS 1.3
  ignores `set_ciphers` entirely, so the weak-cipher probe is pinned to TLS 1.2
  on purpose.
- Configuration of a listener that is firewalled from where you run this.
- Any host the scanner cannot route to.
- Whether a client certificate would be accepted; client auth is untested.
- STARTTLS-wrapped protocols (SMTP, IMAP, LDAP, Postgres). `--port` lets you
  point at one, but the handshake will fail because those protocols require a
  plaintext preamble first. There is no STARTTLS support.

## Environment-dependent results

- The weak-cipher list is what your OpenSSL build offers. Suites disabled at
  security level 2 cannot be tested at all; they are skipped rather than
  reported as "not accepted". Two machines can legitimately produce different
  weak-cipher findings for the same server.
- The live-certificate tests skip when there is no network. A green run on an
  offline runner covers 65 of the 69 tests.
- Certificate expiry is computed against the local clock. A host with a skewed
  clock will draw wrong conclusions about every certificate it checks.

## Not a compliance certificate

Passing this scan means a specific set of checks did not fire. It does not mean
the endpoint is compliant with PCI-DSS, HIPAA, or any other framework, and it
is not a substitute for a qualified assessment.
