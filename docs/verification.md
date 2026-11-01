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
