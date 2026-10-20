## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The C and C++ executables are named `certinfo_c` and `certinfo_cpp`.

## Tests

CTest runs the shared command-line and output conformance suite for the enabled
implementations. Python is used as the test runner; Python implementation checks
are included when the `cryptography` package is installed. See
[`tests/README.md`](tests/README.md) for the behavior contract and instructions
for adding another implementation.

```sh
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## Scope and output

The tool reports certificate validity dates, marking expired and not-yet-valid
certificates; failed validity comparisons are shown as unknown. It does not
validate certificate signatures, chain trust, hostnames, or revocation status,
so these date indicators do not establish that a certificate or chain is
trusted. Bundles are limited to 16 MiB and 1,024 certificates to bound resource
use.

Color is enabled automatically only when stdout is a terminal. `NO_COLOR` and
`TERM=dumb` disable automatic color; use `--color` to force it or `--no-color`
to disable it explicitly. Non-printable and non-ASCII bytes in certificate
common names, DNS SANs, and paths in diagnostics use visible hexadecimal
escapes, preventing untrusted text from injecting terminal control sequences.

## Example

```text
certinfo_cpp chain.crt
#1 - Common Name (CN): R3
    Valid from: Sep  4 00:00:00 2020 GMT
    Valid until: Sep 15 16:00:00 2025 GMT (Expired)
```

Colors are omitted here for readability; the displayed expiration status
reflects the dates in this illustrative example.
