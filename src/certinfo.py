import os
import sys
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID, NameOID

VERSION = "1.4.0"
MAX_BUNDLE_SIZE = 16 * 1024 * 1024
MAX_CERTIFICATES = 1024


def print_help():
    print("Usage: certinfo [--color|--no-color] <path_to_pem_bundle>")
    print("Options:")
    print("  --help       Show help")
    print("  --version    Show version")
    print("  --color      Force color output")
    print("  --no-color   Disable color output")


def use_color(mode):
    if mode == "always":
        return True
    if mode == "never":
        return False
    return (
        not os.environ.get("NO_COLOR")
        and os.environ.get("TERM") != "dumb"
        and sys.stdout.isatty()
    )


def escape_terminal_bytes(value):
    hex_digits = b"0123456789ABCDEF"
    escaped = bytearray()
    for byte in value:
        if 0x20 <= byte <= 0x7E:
            escaped.append(byte)
        else:
            escaped.extend((92, 120, hex_digits[byte >> 4], hex_digits[byte & 0x0F]))
    return escaped.decode("ascii")


def escape_terminal_text(value):
    return escape_terminal_bytes(value.encode("utf-8"))


def escape_path(path):
    return escape_terminal_bytes(os.fsencode(path))


def styled_text(value, style, color):
    if color:
        return f"\033[{style}m{value}\033[0m"
    return value


def format_asn1_time(value):
    months = (
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    )
    return (
        f"{months[value.month - 1]} {value.day:2d} "
        f"{value.hour:02d}:{value.minute:02d}:{value.second:02d} "
        f"{value.year:04d} GMT"
    )


def process_certificate(cert, cert_number, color):
    common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = escape_terminal_text(common_names[0].value) if common_names else "N/A"
    print(
        f"#{cert_number} - Common Name (CN): "
        f"{styled_text(common_name, '1', color)}"
    )

    if hasattr(cert, "not_valid_before_utc"):
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
    else:
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
        now = datetime.now(timezone.utc).replace(tzinfo=None)

    try:
        not_yet_valid = now < not_before
    except (TypeError, ValueError, OverflowError):
        not_yet_valid = None
    try:
        expired = now > not_after
    except (TypeError, ValueError, OverflowError):
        expired = None

    valid_from = styled_text("Valid from:", "33", color)
    print(f"\t{valid_from} {format_asn1_time(not_before)}", end="")
    if not_yet_valid is True:
        print(styled_text(" (Not yet valid)", "1;33", color), end="")
    elif not_yet_valid is None:
        print(styled_text(" (Validity unknown)", "1;35", color), end="")
    print()

    valid_until = "Valid until:"
    if expired is True:
        valid_until = styled_text(valid_until, "1;31", color)
        suffix = styled_text(" (Expired)", "1;31", color)
    elif expired is None:
        valid_until = styled_text(valid_until, "1;35", color)
        suffix = styled_text(" (Validity unknown)", "1;35", color)
    else:
        valid_until = styled_text(valid_until, "33", color)
        suffix = ""
    print(f"\t{valid_until} {format_asn1_time(not_after)}{suffix}")

    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san.value:
            if isinstance(name, x509.DNSName):
                print(f"\tSAN: {escape_terminal_text(name.value)}")
    except ExtensionNotFound:
        pass

    print()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print_help()
        return 0

    if argv == ["--version"]:
        print(f"certinfo version {VERSION}")
        return 0

    mode = "auto"
    if len(argv) == 1:
        bundle_path = argv[0]
    elif len(argv) == 2 and argv[0] == "--color":
        mode = "always"
        bundle_path = argv[1]
    elif len(argv) == 2 and argv[0] == "--no-color":
        mode = "never"
        bundle_path = argv[1]
    else:
        print_help()
        return 1
    color = use_color(mode)

    try:
        with open(bundle_path, "rb") as file:
            pem_data = file.read(MAX_BUNDLE_SIZE + 1)
    except OSError:
        print(f"Cannot open: {escape_path(bundle_path)}", file=sys.stderr)
        return 1

    if len(pem_data) > MAX_BUNDLE_SIZE:
        print("Certificate bundle exceeds the 16 MiB limit.", file=sys.stderr)
        return 1

    begin_marker = b"-----BEGIN CERTIFICATE-----"
    end_marker = b"-----END CERTIFICATE-----"
    cert_number = 1
    offset = 0
    malformed = False
    too_many_certificates = False
    while offset < len(pem_data):
        start = pem_data.find(begin_marker, offset)
        end = pem_data.find(end_marker, offset)
        if end != -1 and (start == -1 or end < start):
            malformed = True
            break
        if start == -1:
            break
        if cert_number > MAX_CERTIFICATES:
            too_many_certificates = True
            break

        end = pem_data.find(end_marker, start + len(begin_marker))
        nested_start = pem_data.find(begin_marker, start + len(begin_marker))
        if end == -1 or (nested_start != -1 and nested_start < end):
            malformed = True
            break

        block_end = end + len(end_marker)
        try:
            cert = x509.load_pem_x509_certificate(pem_data[start:block_end])
        except ValueError:
            malformed = True
            break

        process_certificate(cert, cert_number, color)
        cert_number += 1
        offset = block_end

    if too_many_certificates:
        print(
            "Certificate bundle exceeds the 1024 certificate limit.",
            file=sys.stderr,
        )
        return 1
    if cert_number == 1:
        print("No valid certificates found in the bundle.", file=sys.stderr)
        return 1
    if malformed:
        print("Malformed certificate data in the bundle.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
