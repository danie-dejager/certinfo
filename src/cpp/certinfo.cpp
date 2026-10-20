#include <climits>
#include <cstddef>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>

#include <string>

#ifdef _WIN32
#include <io.h>
#define certinfo_fileno _fileno
#define certinfo_isatty _isatty
#else
#include <unistd.h>
#define certinfo_fileno fileno
#define certinfo_isatty isatty
#endif

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/x509v3.h>
#include "version.h"

static constexpr std::size_t MAX_BUNDLE_SIZE = 16U * 1024U * 1024U;
static constexpr int MAX_CERTIFICATES = 1024;

enum ColorMode {
    COLOR_AUTO,
    COLOR_ALWAYS,
    COLOR_NEVER
};

static bool use_color(ColorMode mode) {
    if (mode == COLOR_ALWAYS)
        return true;
    if (mode == COLOR_NEVER)
        return false;

    const char* no_color = std::getenv("NO_COLOR");
    const char* term = std::getenv("TERM");
    return !(no_color && no_color[0] != '\0') &&
           !(term && std::string(term) == "dumb") &&
           certinfo_isatty(certinfo_fileno(stdout));
}

static void print_styled_text(
    const std::string& text, const char* style, bool color) {
    if (color)
        std::cout << static_cast<char>(27) << "[" << style << "m";
    std::cout << text;
    if (color)
        std::cout << static_cast<char>(27) << "[0m";
}

static std::string escape_terminal_text(const std::string& text) {
    static const char hex[] = "0123456789ABCDEF";
    std::string escaped;
    for (unsigned char value : text) {
        if (value >= 0x20 && value <= 0x7e) {
            escaped.push_back(static_cast<char>(value));
        } else {
            escaped.push_back(static_cast<char>(92));
            escaped.push_back('x');
            escaped.push_back(hex[value >> 4]);
            escaped.push_back(hex[value & 0x0f]);
        }
    }
    return escaped;
}

static std::string ASN1_TIME_to_string(const ASN1_TIME* time) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "BIO error";

    if (!ASN1_TIME_print(bio, time)) {
        BIO_free(bio);
        return "Invalid time";
    }

    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    if (len <= 0 || !data) {
        BIO_free(bio);
        return "Time read error";
    }

    std::string result(data, static_cast<std::size_t>(len));
    BIO_free(bio);
    return result;
}

static std::string ASN1_STRING_to_string(const ASN1_STRING* value) {
    unsigned char* utf8 = nullptr;
    int len = ASN1_STRING_to_UTF8(&utf8, value);
    if (len < 0) return {};

    std::string result(reinterpret_cast<char*>(utf8), static_cast<std::size_t>(len));
    OPENSSL_free(utf8);
    return result;
}

static void processCertificate(X509* cert, int index, bool color) {
    X509_NAME* subject = X509_get_subject_name(cert);
    int common_name_index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);

    std::cout << "#" << index << " - Common Name (CN): ";
    if (common_name_index >= 0) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, common_name_index);
        ASN1_STRING* common_name = X509_NAME_ENTRY_get_data(entry);
        print_styled_text(
            escape_terminal_text(ASN1_STRING_to_string(common_name)), "1", color);
    } else {
        print_styled_text("N/A", "1", color);
    }
    std::cout << "\n";

    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    int not_before_comparison = X509_cmp_current_time(not_before);
    int not_after_comparison = X509_cmp_current_time(not_after);

    std::cout << "\t";
    print_styled_text("Valid from:", "33", color);
    std::cout << " " << ASN1_TIME_to_string(not_before);
    if (not_before_comparison > 0) {
        print_styled_text(" (Not yet valid)", "1;33", color);
    } else if (not_before_comparison == 0) {
        print_styled_text(" (Validity unknown)", "1;35", color);
    }
    std::cout << "\n";

    std::cout << "\t";
    if (not_after_comparison < 0) {
        print_styled_text("Valid until:", "1;31", color);
        std::cout << " " << ASN1_TIME_to_string(not_after);
        print_styled_text(" (Expired)", "1;31", color);
    } else if (not_after_comparison == 0) {
        print_styled_text("Valid until:", "1;35", color);
        std::cout << " " << ASN1_TIME_to_string(not_after);
        print_styled_text(" (Validity unknown)", "1;35", color);
    } else {
        print_styled_text("Valid until:", "33", color);
        std::cout << " " << ASN1_TIME_to_string(not_after);
    }
    std::cout << "\n";

    GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (names) {
        int count = sk_GENERAL_NAME_num(names);
        for (int i = 0; i < count; i++) {
            GENERAL_NAME* name = sk_GENERAL_NAME_value(names, i);
            if (name->type == GEN_DNS) {
                std::cout << "\tSAN: "
                          << escape_terminal_text(
                                 ASN1_STRING_to_string(name->d.dNSName))
                          << "\n";
            }
        }
        GENERAL_NAMES_free(names);
    }
}

static void print_help() {
    std::cout << "Usage: certinfo [--color|--no-color] <path_to_pem_bundle>\n";
    std::cout << "Options:\n";
    std::cout << "  --help       Show help\n";
    std::cout << "  --version    Show version\n";
    std::cout << "  --color      Force color output\n";
    std::cout << "  --no-color   Disable color output\n";
}

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string(argv[1]) == "--help") {
        print_help();
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--version") {
        std::cout << "certinfo version " << CERTINFO_VERSION << "\n";
        return 0;
    }

    const char* path = nullptr;
    ColorMode mode = COLOR_AUTO;
    if (argc == 2) {
        path = argv[1];
    } else if (argc == 3 && std::string(argv[1]) == "--color") {
        path = argv[2];
        mode = COLOR_ALWAYS;
    } else if (argc == 3 && std::string(argv[1]) == "--no-color") {
        path = argv[2];
        mode = COLOR_NEVER;
    } else {
        print_help();
        return 1;
    }
    bool color = use_color(mode);

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open: " << escape_terminal_text(path) << "\n";
        return 1;
    }

    file.seekg(0, std::ios::end);
    std::streamoff file_size = file.tellg();
    if (file_size < 0) {
        std::cerr << "Cannot read: " << escape_terminal_text(path) << "\n";
        return 1;
    }
    if (file_size > static_cast<std::streamoff>(MAX_BUNDLE_SIZE)) {
        std::cerr << "Certificate bundle exceeds the 16 MiB limit.\n";
        return 1;
    }
    file.seekg(0, std::ios::beg);
    if (!file) {
        std::cerr << "Cannot read: " << escape_terminal_text(path) << "\n";
        return 1;
    }

    std::string data(static_cast<std::size_t>(file_size), char{});
    if (file_size > 0 &&
        !file.read(data.data(), static_cast<std::streamsize>(file_size))) {
        std::cerr << "Cannot read: " << escape_terminal_text(path) << "\n";
        return 1;
    }

    static const std::string begin_marker = "-----BEGIN CERTIFICATE-----";
    static const std::string end_marker = "-----END CERTIFICATE-----";
    std::size_t offset = 0;
    int index = 1;
    bool malformed = false;
    bool too_many_certificates = false;

    while (offset < data.size()) {
        std::size_t begin = data.find(begin_marker, offset);
        std::size_t end = data.find(end_marker, offset);
        if (end != std::string::npos &&
            (begin == std::string::npos || end < begin)) {
            malformed = true;
            break;
        }
        if (begin == std::string::npos)
            break;
        if (index > MAX_CERTIFICATES) {
            too_many_certificates = true;
            break;
        }

        std::size_t block_end = data.find(end_marker, begin + begin_marker.size());
        std::size_t nested_begin = data.find(begin_marker, begin + begin_marker.size());
        if (block_end == std::string::npos ||
            (nested_begin != std::string::npos && nested_begin < block_end)) {
            malformed = true;
            break;
        }

        std::size_t block_end_position = block_end + end_marker.size();
        std::size_t block_length = block_end_position - begin;
        if (block_length > INT_MAX) {
            malformed = true;
            break;
        }

        BIO* certificate_bio = BIO_new_mem_buf(
            data.data() + begin, static_cast<int>(block_length));
        X509* cert = certificate_bio
            ? PEM_read_bio_X509(certificate_bio, nullptr, nullptr, nullptr)
            : nullptr;
        BIO_free(certificate_bio);
        if (!cert) {
            malformed = true;
            break;
        }

        processCertificate(cert, index++, color);
        std::cout << "\n";
        X509_free(cert);
        offset = block_end_position;
    }

    if (too_many_certificates) {
        std::cerr << "Certificate bundle exceeds the 1024 certificate limit.\n";
        return 1;
    }
    if (index == 1) {
        std::cerr << "No valid certificates found in the bundle.\n";
        return 1;
    }
    if (malformed) {
        std::cerr << "Malformed certificate data in the bundle.\n";
        return 1;
    }
    return 0;
}
