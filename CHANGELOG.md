# Changelog

Notable changes to certinfo are documented here.

## 1.4.0

### Added

- Mark certificates that are not yet valid and show validity-comparison errors
  as unknown rather than treating them as valid.
- Escape certificate-derived text and paths in diagnostics; add automatic,
  force, and disable color output modes.
- Limit bundles to 16 MiB and 1,024 certificates to bound resource use.

## 1.3.0

### Added

- Add CTest conformance checks that compare the C, C++, and available Python
  implementations using shared generated certificate fixtures.
- Add command-line behavior checks for help, version, missing files, and invalid
  or empty PEM bundles.
- Detect malformed or truncated certificate data after readable certificates.

### Changed

- Align help, version, and no-certificate messages across implementations.
- Return a failure status when a bundle contains no readable certificates.
- Decode C certificate common names as UTF-8, matching the other versions.
- Link the C and C++ tools only against OpenSSL Crypto.
