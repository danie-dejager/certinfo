# Project guide

## Purpose

Certinfo is an educational project demonstrating how the same small certificate
inspection tool can be implemented in different languages. The implementations
should perform the same operations and produce the same command-line behavior
and output. The C and C++ programs are built by CMake; a Python implementation
is also present, and additional languages such as Go may be added later.

This is an informational PEM bundle inspector. It displays certificate fields
and highlights expiration; it does **not** verify signatures, chain trust,
hostnames, or revocation. Do not describe an unexpired bundle as a trusted or
valid chain.

## Implementations

- `src/c/certinfo.c` — C implementation.
- `src/cpp/certinfo.cpp` — C++ implementation.
- `src/certinfo.py` — Python implementation; requires `cryptography`.
- `src/version.h.in` — CMake-generated version header for the compiled tools.

Keep implementation behavior aligned. The conformance suite in `tests/` is the
shared contract for CLI output, exit status, and certificate display. When
changing visible behavior, update the implementations and tests together.

## Validation environment

Prefer building and testing from the WSL Linux environment used to open this
project in Zed. At the start of validation, confirm the active shell and the
toolchains needed by the changed code; do not infer availability from the host
OS or from an earlier session. For this project, the core checks need CMake, a C
compiler, a C++ compiler, OpenSSL development files, and Python 3. If a future
change adds another implementation (for example Go), check that language's
compiler too.

If the active environment is Windows, check whether the repository is
accessible from WSL and run Linux build/test commands there when possible. If
neither WSL nor the required native tools are available, continue with static
review but clearly report that build/tests could not be run. Never report tests
as passing unless they ran successfully. Use a separate build directory for
WSL; Windows and Linux CMake build outputs are not interchangeable.

## Build and test in WSL

Install the native build dependencies on Ubuntu/Debian:

```sh
sudo apt update
sudo apt install build-essential cmake libssl-dev python3
```

Configure and build out of tree, then run the conformance suite:

```sh
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

CTest uses Python's standard library as its runner. The Python implementation
is added to conformance testing when `cryptography` is installed in the Python
environment visible to CMake at configure time. Reconfigure after changing that
environment. The C and C++ fixture generator uses the project's OpenSSL
library dependency.

The CMake options `BUILD_C` and `BUILD_CPP` control their respective targets.
The resulting executables are `certinfo_c` and `certinfo_cpp`.

## Adding another language

1. Implement the same CLI and output behavior as the existing programs.
2. Add a CMake target when that language has a CMake-supported build workflow.
3. Pass its executable to `tests/conformance.py` as another
   `--implementation NAME=PATH` argument.
4. Run the complete CTest suite and keep the output byte-for-byte aligned for
   shared fixtures.

The generated valid and expired certificates in `tests/` avoid depending on a
stale, hand-maintained certificate fixture. Extend the suite when adding new
observable behavior or edge-case handling.

## Current follow-up areas

- Consider optional actual chain validation as a separate feature, with an
  explicit trust-store and hostname policy.
