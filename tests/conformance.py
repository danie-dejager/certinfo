import argparse
import os
import re
import subprocess
import sys
import tempfile


HELP = (
    "Usage: certinfo [--color|--no-color] <path_to_pem_bundle>\n"
    "Options:\n"
    "  --help       Show help\n"
    "  --version    Show version\n"
    "  --color      Force color output\n"
    "  --no-color   Disable color output\n"
)
NO_CERTIFICATES = "No valid certificates found in the bundle.\n"
MALFORMED_CERTIFICATE = "Malformed certificate data in the bundle.\n"
MAX_BUNDLE_SIZE = 16 * 1024 * 1024
MAX_CERTIFICATES = 1024


def run(command, arguments):
    return subprocess.run(
        [*command, *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def assert_result(label, implementations, arguments, expected_code, expected_stdout, expected_stderr):
    results = []
    for name, command in implementations:
        result = run(command, arguments)
        actual = (result.returncode, result.stdout, result.stderr)
        expected = (expected_code, expected_stdout, expected_stderr)
        if actual != expected:
            raise AssertionError(
                f"{label}: {name} returned {actual!r}; expected {expected!r}"
            )
        results.append((name, actual))

    baseline_name, baseline = results[0]
    for name, result in results[1:]:
        if result != baseline:
            raise AssertionError(
                f"{label}: output differs between {baseline_name} and {name}"
            )


def assert_certificate_output(implementations, certificate_path, expected_status=None):
    results = []
    for name, command in implementations:
        result = run(command, [str(certificate_path)])
        if result.returncode != 0 or result.stderr:
            raise AssertionError(
                f"certificate fixture: {name} returned {result.returncode}; "
                f"stdout={result.stdout!r}, stderr={result.stderr!r}"
            )
        for expected in (
            "#1 - Common Name (CN): CertInfo Conformance Test",
            "Valid from:",
            "Valid until:",
            "SAN: certinfo.example.test",
        ):
            if expected not in result.stdout:
                raise AssertionError(
                    f"certificate fixture: {name} did not print {expected!r}: "
                    f"{result.stdout!r}"
                )
        for status in ("(Expired)", "(Not yet valid)", "(Validity unknown)"):
            if (status in result.stdout) != (status == expected_status):
                raise AssertionError(
                    f"certificate fixture: {name} had unexpected validity output: "
                    f"{result.stdout!r}"
                )
        results.append((name, result.stdout))

    baseline_name, baseline = results[0]
    for name, output in results[1:]:
        if output != baseline:
            raise AssertionError(
                f"certificate output differs between {baseline_name} and {name}:\n"
                f"{baseline!r}\n{output!r}"
            )
    return baseline


def assert_color_options(implementations, certificate_path, plain_output):
    for name, command in implementations:
        colored = run(command, ["--color", str(certificate_path)])
        if colored.returncode != 0 or "\033[" not in colored.stdout:
            raise AssertionError(
                f"forced color: {name} did not emit ANSI color: {colored.stdout!r}"
            )
        if re.sub(r"\033\[[0-9;]*m", "", colored.stdout) != plain_output:
            raise AssertionError(f"forced color: {name} changed certificate content")

        uncolored = run(command, ["--no-color", str(certificate_path)])
        if (uncolored.returncode, uncolored.stdout, uncolored.stderr) != (
            0, plain_output, ""
        ):
            raise AssertionError(
                f"disabled color: {name} returned "
                f"{(uncolored.returncode, uncolored.stdout, uncolored.stderr)!r}"
            )


def assert_escaped_certificate(implementations, certificate_path):
    expected = (
        "#1 - Common Name (CN): Danger\\x1B[2J\\x0AForged",
        "SAN: safe\\x1B[2J\\x0Aforged.example",
    )
    outputs = []
    for name, command in implementations:
        result = run(command, [str(certificate_path)])
        if result.returncode != 0 or result.stderr:
            raise AssertionError(
                f"escaped certificate: {name} returned {result.returncode}; "
                f"stderr={result.stderr!r}"
            )
        if any(text not in result.stdout for text in expected):
            raise AssertionError(
                f"escaped certificate: {name} did not escape CN/SAN text: "
                f"{result.stdout!r}"
            )
        if chr(27) in result.stdout:
            raise AssertionError(
                f"escaped certificate: {name} emitted an untrusted escape sequence"
            )
        outputs.append((name, result.stdout))

    baseline_name, baseline = outputs[0]
    for name, output in outputs[1:]:
        if output != baseline:
            raise AssertionError(
                f"escaped certificate output differs between {baseline_name} and {name}"
            )


def escape_path(path):
    return "".join(
        chr(byte) if 0x20 <= byte <= 0x7E else f"\\x{byte:02X}"
        for byte in os.fsencode(path)
    )


def assert_certificate_count_limit(implementations, bundle_path):
    results = []
    for name, command in implementations:
        result = run(command, [str(bundle_path)])
        expected_stderr = "Certificate bundle exceeds the 1024 certificate limit.\n"
        if result.returncode != 1 or result.stderr != expected_stderr:
            raise AssertionError(
                f"certificate-count limit: {name} returned "
                f"{(result.returncode, result.stderr)!r}"
            )
        if result.stdout.count(" - Common Name (CN): ") != MAX_CERTIFICATES:
            raise AssertionError(
                f"certificate-count limit: {name} printed an unexpected count"
            )
        results.append((name, result.stdout, result.stderr))

    baseline_name, baseline_stdout, baseline_stderr = results[0]
    for name, stdout, stderr in results[1:]:
        if (stdout, stderr) != (baseline_stdout, baseline_stderr):
            raise AssertionError(
                f"certificate-count limit differs between {baseline_name} and {name}"
            )


def assert_malformed_after_valid(implementations, bundle_path, expected_stdout):
    results = []
    for name, command in implementations:
        result = run(command, [str(bundle_path)])
        actual = (result.returncode, result.stdout, result.stderr)
        expected = (1, expected_stdout, MALFORMED_CERTIFICATE)
        if actual != expected:
            raise AssertionError(
                f"malformed data after valid certificate: {name} returned "
                f"{actual!r}; expected {expected!r}"
            )
        results.append((name, actual))

    baseline_name, baseline = results[0]
    for name, result in results[1:]:
        if result != baseline:
            raise AssertionError(
                f"malformed bundle result differs between {baseline_name} and {name}"
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--generator", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--implementation", action="append", default=[])
    parser.add_argument("--python-script")
    args = parser.parse_args()

    implementations = []
    for implementation in args.implementation:
        name, executable = implementation.split("=", 1)
        implementations.append((name, [executable]))
    if args.python_script:
        implementations.append(("Python", [sys.executable, args.python_script]))
    if not implementations:
        raise AssertionError("No implementations were provided")

    assert_result("help", implementations, ["--help"], 0, HELP, "")
    assert_result(
        "version", implementations, ["--version"], 0,
        f"certinfo version {args.version}\n", ""
    )
    assert_result("usage", implementations, [], 1, HELP, "")

    with tempfile.TemporaryDirectory(prefix="certinfo-conformance-") as temp_dir:
        missing_path = os.path.join(temp_dir, "missing.pem")
        assert_result(
            "missing file", implementations, [str(missing_path)], 1, "",
            f"Cannot open: {missing_path}\n",
        )
        if os.name == "posix":
            control_path = os.path.join(
                temp_dir, f"missing-{chr(27)}[31m\n.pem"
            )
            assert_result(
                "control characters in path", implementations,
                [control_path], 1, "",
                f"Cannot open: {escape_path(control_path)}\n",
            )

        oversized_path = os.path.join(temp_dir, "oversized.pem")
        with open(oversized_path, "wb") as oversized_file:
            oversized_file.truncate(MAX_BUNDLE_SIZE + 1)
        assert_result(
            "oversized bundle", implementations, [oversized_path], 1, "",
            "Certificate bundle exceeds the 16 MiB limit.\n",
        )

        empty_path = os.path.join(temp_dir, "empty.pem")
        with open(empty_path, "wb"):
            pass
        assert_result(
            "empty bundle", implementations, [str(empty_path)], 1, "",
            NO_CERTIFICATES,
        )

        malformed_path = os.path.join(temp_dir, "malformed.pem")
        with open(malformed_path, "w", encoding="ascii") as malformed_file:
            malformed_file.write("not a PEM certificate\n")
        assert_result(
            "malformed bundle", implementations, [str(malformed_path)], 1, "",
            NO_CERTIFICATES,
        )

        valid_certificate_path = None
        valid_certificate_output = None
        for validity, expected_status in (
            ("valid", None), ("expired", "(Expired)"),
            ("future", "(Not yet valid)"),
        ):
            certificate_path = os.path.join(temp_dir, f"{validity}.pem")
            subprocess.run(
                [args.generator, str(certificate_path), validity],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            output = assert_certificate_output(
                implementations, certificate_path, expected_status
            )
            if validity == "valid":
                valid_certificate_path = certificate_path
                valid_certificate_output = output

        if valid_certificate_path is None or valid_certificate_output is None:
            raise AssertionError("valid certificate fixture was not generated")
        assert_color_options(
            implementations, valid_certificate_path, valid_certificate_output
        )

        unsafe_certificate_path = os.path.join(temp_dir, "unsafe-text.pem")
        subprocess.run(
            [args.generator, unsafe_certificate_path, "valid", "unsafe"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        assert_escaped_certificate(implementations, unsafe_certificate_path)

        with open(valid_certificate_path, "rb") as certificate_file:
            valid_certificate = certificate_file.read()

        count_limit_path = os.path.join(temp_dir, "certificate-count-limit.pem")
        if len(valid_certificate) * (MAX_CERTIFICATES + 1) >= MAX_BUNDLE_SIZE:
            raise AssertionError("generated certificate is too large for count-limit test")
        with open(count_limit_path, "wb") as count_limit_file:
            count_limit_file.write(valid_certificate * (MAX_CERTIFICATES + 1))
        assert_certificate_count_limit(implementations, count_limit_path)

        truncated_path = os.path.join(temp_dir, "truncated-after-valid.pem")
        with open(truncated_path, "wb") as truncated_file:
            truncated_file.write(
                valid_certificate + b"\n-----BEGIN CERTIFICATE-----\nnot-base64\n"
            )
        assert_malformed_after_valid(
            implementations, truncated_path, valid_certificate_output
        )

        malformed_path = os.path.join(temp_dir, "malformed-after-valid.pem")
        with open(malformed_path, "wb") as malformed_file:
            malformed_file.write(
                valid_certificate
                + b"\n-----BEGIN CERTIFICATE-----\nnot-base64\n"
                + b"-----END CERTIFICATE-----\n"
            )
        assert_malformed_after_valid(
            implementations, malformed_path, valid_certificate_output
        )

    print(f"Conformance checks passed for {len(implementations)} implementation(s).")


if __name__ == "__main__":
    main()
