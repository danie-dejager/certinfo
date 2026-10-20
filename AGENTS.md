# Repository instructions

## Environment and validation

- Prefer the WSL Linux environment in which this project is opened in Zed for
  builds and tests.
- Before validating, check the active environment and required tools rather
  than assuming they are available. The core C/C++ checks require CMake, C and
  C++ compilers, OpenSSL development headers/libraries, and Python 3.
- If the agent shell is Windows, check whether WSL is available and whether the
  project directory can be reached from it. Run the build and tests in WSL when
  possible. Keep WSL and Windows CMake build directories separate.
- If WSL is unavailable, use the current environment only if the required
  compiler, CMake, and OpenSSL development files are present. Otherwise, do
  static checks and state clearly that native validation was unavailable.
- Do not claim a build or test passed unless the command was run and succeeded.
- When a new language implementation is added, check for its compiler/runtime
  and include it in the conformance test run when available.

Use the commands in `PROJECT.md` for the standard configure, build, and CTest
workflow. Keep implementations behaviorally aligned; update the shared
conformance suite whenever CLI output or exit behavior changes.
