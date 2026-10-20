# Conformance tests

`conformance.py` defines the shared command-line and output contract for each
implementation. It compares exact stdout, stderr, and exit status for the same
inputs. Certificate fixtures are generated during the test run with OpenSSL,
so their validity periods stay relative to the current time instead of going
stale.

The suite currently covers help/version output, usage errors, missing, empty,
and malformed files; valid, expired, and not-yet-valid certificates; escaped
certificate text and error paths; color options; bundle-size and certificate
count limits; and malformed or truncated blocks following a readable
certificate. CMake passes each available executable to the runner as an
`--implementation NAME=PATH` argument. Future implementations can use the same
runner without a separate test framework.

The Python implementation is included when Python's `cryptography` package is
installed. The test runner itself uses only the Python standard library.
