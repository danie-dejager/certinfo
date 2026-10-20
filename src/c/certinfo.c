#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#define MAX_STRING_LENGTH 256
#define MAX_BUNDLE_SIZE (16U * 1024U * 1024U)
#define MAX_CERTIFICATES 1024

typedef enum {
    COLOR_AUTO,
    COLOR_ALWAYS,
    COLOR_NEVER
} color_mode;

static void print_help(void) {
    printf("Usage: certinfo [--color|--no-color] <path_to_pem_bundle>\n");
    printf("Options:\n");
    printf("  --help       Show help\n");
    printf("  --version    Show version\n");
    printf("  --color      Force color output\n");
    printf("  --no-color   Disable color output\n");
}

static int use_color(color_mode mode) {
    if (mode == COLOR_ALWAYS)
        return 1;
    if (mode == COLOR_NEVER)
        return 0;

    const char* no_color = getenv("NO_COLOR");
    const char* term = getenv("TERM");
    return !(no_color && no_color[0] != '\0') &&
           !(term && strcmp(term, "dumb") == 0) &&
           certinfo_isatty(certinfo_fileno(stdout));
}

static void print_styled_text(const char* text, const char* style, int color) {
    if (color)
        printf("%c[%sm", 27, style);
    fputs(text, stdout);
    if (color)
        printf("%c[0m", 27);
}

static void print_escaped_text(
    FILE* output, const unsigned char* text, size_t length) {
    for (size_t i = 0; i < length; i++) {
        unsigned char value = text[i];
        if (value >= 0x20 && value <= 0x7e) {
            fputc(value, output);
        } else {
            fputc(92, output);
            fprintf(output, "x%02X", value);
        }
    }
}

static void ASN1_TIME_to_string(const ASN1_TIME* t, char* out, size_t out_size) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        snprintf(out, out_size, "BIO error");
        return;
    }

    if (!ASN1_TIME_print(bio, t)) {
        snprintf(out, out_size, "Invalid time");
        BIO_free(bio);
        return;
    }

    int len = BIO_read(bio, out, (int)(out_size - 1));
    if (len <= 0) {
        snprintf(out, out_size, "Time read error");
        BIO_free(bio);
        return;
    }

    out[len] = '\0';
    BIO_free(bio);
}

static void processCertificate(X509* cert, int index, int color) {
    char buffer[MAX_STRING_LENGTH];
    X509_NAME* subject = X509_get_subject_name(cert);
    int cn_index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);

    printf("#%d - Common Name (CN): ", index);
    if (cn_index >= 0) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, cn_index);
        ASN1_STRING* common_name = X509_NAME_ENTRY_get_data(entry);
        unsigned char* utf8 = NULL;
        int utf8_len = ASN1_STRING_to_UTF8(&utf8, common_name);
        if (utf8_len >= 0) {
            if (color)
                printf("%c[1m", 27);
            print_escaped_text(stdout, utf8, (size_t)utf8_len);
            if (color)
                printf("%c[0m", 27);
            putchar(10);
            OPENSSL_free(utf8);
        } else {
            print_styled_text("N/A", "1", color);
            putchar(10);
        }
    } else {
        print_styled_text("N/A", "1", color);
        putchar(10);
    }

    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    int not_before_comparison = X509_cmp_current_time(not_before);
    int not_after_comparison = X509_cmp_current_time(not_after);

    ASN1_TIME_to_string(not_before, buffer, sizeof(buffer));
    putchar(9);
    print_styled_text("Valid from:", "33", color);
    printf(" %s", buffer);
    if (not_before_comparison > 0) {
        print_styled_text(" (Not yet valid)", "1;33", color);
    } else if (not_before_comparison == 0) {
        print_styled_text(" (Validity unknown)", "1;35", color);
    }
    putchar(10);

    ASN1_TIME_to_string(not_after, buffer, sizeof(buffer));
    putchar(9);
    if (not_after_comparison < 0) {
        print_styled_text("Valid until:", "1;31", color);
        printf(" %s", buffer);
        print_styled_text(" (Expired)", "1;31", color);
    } else if (not_after_comparison == 0) {
        print_styled_text("Valid until:", "1;35", color);
        printf(" %s", buffer);
        print_styled_text(" (Validity unknown)", "1;35", color);
    } else {
        print_styled_text("Valid until:", "33", color);
        printf(" %s", buffer);
    }
    putchar(10);

    GENERAL_NAMES* names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (names) {
        int count = sk_GENERAL_NAME_num(names);
        for (int i = 0; i < count; i++) {
            GENERAL_NAME* name = sk_GENERAL_NAME_value(names, i);
            if (name->type == GEN_DNS) {
                ASN1_STRING* dns = name->d.dNSName;
                int len = ASN1_STRING_length(dns);
                const unsigned char* data = ASN1_STRING_get0_data(dns);
                if (len >= 0) {
                    fputs("\tSAN: ", stdout);
                    print_escaped_text(stdout, data, (size_t)len);
                    putchar(10);
                }
            }
        }
        GENERAL_NAMES_free(names);
    }
}

static const unsigned char* find_marker(
    const unsigned char* data, size_t data_length, size_t start,
    const char* marker, size_t marker_length) {
    if (marker_length > data_length || start > data_length - marker_length)
        return NULL;

    for (size_t i = start; i <= data_length - marker_length; i++) {
        if (memcmp(data + i, marker, marker_length) == 0)
            return data + i;
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        print_help();
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("certinfo version %s\n", CERTINFO_VERSION);
        return 0;
    }

    const char* path = NULL;
    color_mode mode = COLOR_AUTO;
    if (argc == 2) {
        path = argv[1];
    } else if (argc == 3 && strcmp(argv[1], "--color") == 0) {
        path = argv[2];
        mode = COLOR_ALWAYS;
    } else if (argc == 3 && strcmp(argv[1], "--no-color") == 0) {
        path = argv[2];
        mode = COLOR_NEVER;
    } else {
        print_help();
        return 1;
    }
    int color = use_color(mode);

    FILE* file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "Cannot open: ");
        print_escaped_text(stderr, (const unsigned char*)path, strlen(path));
        fputc(10, stderr);
        return 1;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        fprintf(stderr, "Cannot read: ");
        print_escaped_text(stderr, (const unsigned char*)path, strlen(path));
        fputc(10, stderr);
        return 1;
    }
    long file_size = ftell(file);
    if (file_size < 0) {
        fclose(file);
        fprintf(stderr, "Cannot read: ");
        print_escaped_text(stderr, (const unsigned char*)path, strlen(path));
        fputc(10, stderr);
        return 1;
    }
    if ((unsigned long)file_size > MAX_BUNDLE_SIZE) {
        fclose(file);
        fprintf(stderr, "Certificate bundle exceeds the 16 MiB limit.\n");
        return 1;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        fprintf(stderr, "Cannot read: ");
        print_escaped_text(stderr, (const unsigned char*)path, strlen(path));
        fputc(10, stderr);
        return 1;
    }

    size_t data_length = (size_t)file_size;
    unsigned char* data = malloc(data_length ? data_length : 1);
    if (!data || (data_length > 0 && fread(data, 1, data_length, file) != data_length)) {
        free(data);
        fclose(file);
        fprintf(stderr, "Cannot read: ");
        print_escaped_text(stderr, (const unsigned char*)path, strlen(path));
        fputc(10, stderr);
        return 1;
    }
    fclose(file);

    static const char begin_marker[] = "-----BEGIN CERTIFICATE-----";
    static const char end_marker[] = "-----END CERTIFICATE-----";
    const size_t begin_length = sizeof(begin_marker) - 1;
    const size_t end_length = sizeof(end_marker) - 1;
    size_t offset = 0;
    int index = 1;
    int malformed = 0;
    int too_many_certificates = 0;

    while (offset < data_length) {
        const unsigned char* begin = find_marker(
            data, data_length, offset, begin_marker, begin_length);
        const unsigned char* end = find_marker(
            data, data_length, offset, end_marker, end_length);
        if (end && (!begin || end < begin)) {
            malformed = 1;
            break;
        }
        if (!begin)
            break;
        if (index > MAX_CERTIFICATES) {
            too_many_certificates = 1;
            break;
        }

        size_t begin_position = (size_t)(begin - data);
        const unsigned char* block_end = find_marker(
            data, data_length, begin_position + begin_length,
            end_marker, end_length);
        const unsigned char* nested_begin = find_marker(
            data, data_length, begin_position + begin_length,
            begin_marker, begin_length);
        if (!block_end || (nested_begin && nested_begin < block_end)) {
            malformed = 1;
            break;
        }

        size_t block_end_position = (size_t)(block_end - data) + end_length;
        size_t block_length = block_end_position - begin_position;
        if (block_length > INT_MAX) {
            malformed = 1;
            break;
        }

        BIO* certificate_bio = BIO_new_mem_buf(
            data + begin_position, (int)block_length);
        X509* cert = certificate_bio
            ? PEM_read_bio_X509(certificate_bio, NULL, NULL, NULL)
            : NULL;
        BIO_free(certificate_bio);
        if (!cert) {
            malformed = 1;
            break;
        }

        processCertificate(cert, index++, color);
        printf("\n");
        X509_free(cert);
        offset = block_end_position;
    }

    free(data);
    if (too_many_certificates) {
        fprintf(stderr, "Certificate bundle exceeds the 1024 certificate limit.\n");
        return 1;
    }
    if (index == 1) {
        fprintf(stderr, "No valid certificates found in the bundle.\n");
        return 1;
    }
    if (malformed) {
        fprintf(stderr, "Malformed certificate data in the bundle.\n");
        return 1;
    }
    return 0;
}
