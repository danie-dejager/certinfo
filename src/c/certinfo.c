#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/x509v3.h>
#include "version.h"

#define MAX_STRING_LENGTH 256

static void print_help(const char* program_name) {
    printf("Usage: %s <path_to_pem_bundle>\n", program_name);
    printf("Options:\n");
    printf("  --help     Show help\n");
    printf("  --version  Show version\n");
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

    int len = BIO_read(bio, out, out_size - 1);
    if (len <= 0) {
        snprintf(out, out_size, "Time read error");
        BIO_free(bio);
        return;
    }

    out[len] = '\0';
    BIO_free(bio);
}

static void processCertificate(X509* cert, int index) {
    char buffer[MAX_STRING_LENGTH];

    // Common Name
    X509_NAME* subject = X509_get_subject_name(cert);
    int cn_index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);

    printf("#%d - Common Name (CN): ", index);

    if (cn_index >= 0) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, cn_index);
        ASN1_STRING* cn_asn1 = X509_NAME_ENTRY_get_data(entry);
        int len = ASN1_STRING_length(cn_asn1);
        const unsigned char* data = ASN1_STRING_get0_data(cn_asn1);
        printf("\033[1m%.*s\033[0m\n", len, data);
    } else {
        printf("\033[1mN/A\033[0m\n");
    }

    // Validity
    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after  = X509_get0_notAfter(cert);

    ASN1_TIME_to_string(not_before, buffer, sizeof(buffer));
    printf("\t\033[33mValid from:\033[0m %s\n", buffer);

    ASN1_TIME_to_string(not_after, buffer, sizeof(buffer));
    if (X509_cmp_current_time(not_after) < 0)
        printf("\t\033[1;31mValid until:\033[0m \033[1;31m%s (Expired)\033[0m\n", buffer);
    else
        printf("\t\033[33mValid until:\033[0m %s\n", buffer);

    // SAN
    GENERAL_NAMES* names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (names) {
        int count = sk_GENERAL_NAME_num(names);
        for (int i = 0; i < count; i++) {
            GENERAL_NAME* name = sk_GENERAL_NAME_value(names, i);
            if (name->type == GEN_DNS) {
                ASN1_STRING* dns = name->d.dNSName;
                int len = ASN1_STRING_length(dns);
                const unsigned char* data = ASN1_STRING_get0_data(dns);
                printf("\tSAN: %.*s\n", len, data);
            }
        }
        GENERAL_NAMES_free(names);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        print_help(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0) {
        print_help(argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "--version") == 0) {
        printf("certinfo_c version %s\n", CERTINFO_VERSION);
        return 0;
    }

    const char* path = argv[1];
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open: %s\n", path);
        return 1;
    }

    X509* cert;
    int index = 1;

    while ((cert = PEM_read_X509(f, NULL, NULL, NULL))) {
        processCertificate(cert, index++);
        X509_free(cert);
    }

    fclose(f);
    return 0;
}
