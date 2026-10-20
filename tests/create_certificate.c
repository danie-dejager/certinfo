#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static int write_certificate(const char* path, const char* validity, int unsafe_text) {
    EVP_PKEY_CTX* key_context = NULL;
    EVP_PKEY* key = NULL;
    X509* cert = NULL;
    X509_EXTENSION* san_extension = NULL;
    GENERAL_NAMES* subject_alt_names = NULL;
    GENERAL_NAME* dns_name = NULL;
    ASN1_IA5STRING* dns_value = NULL;
    FILE* output = NULL;
    long not_before_offset;
    long not_after_offset;
    int result = 1;

    if (strcmp(validity, "valid") == 0) {
        not_before_offset = -86400;
        not_after_offset = 31536000;
    } else if (strcmp(validity, "expired") == 0) {
        not_before_offset = -172800;
        not_after_offset = -86400;
    } else if (strcmp(validity, "future") == 0) {
        not_before_offset = 86400;
        not_after_offset = 172800;
    } else {
        fprintf(stderr, "Unknown validity scenario: %s\n", validity);
        return 2;
    }

    key_context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!key_context || EVP_PKEY_keygen_init(key_context) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(key_context, 2048) <= 0 ||
        EVP_PKEY_keygen(key_context, &key) <= 0) {
        goto cleanup;
    }

    cert = X509_new();
    if (!cert || X509_set_version(cert, 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1 ||
        !X509_gmtime_adj(X509_getm_notBefore(cert), not_before_offset) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert), not_after_offset) ||
        X509_set_pubkey(cert, key) != 1) {
        goto cleanup;
    }

    X509_NAME* subject = X509_get_subject_name(cert);
    static const unsigned char common_name[] = "CertInfo Conformance Test";
    static const unsigned char unsafe_common_name[] = {
        'D', 'a', 'n', 'g', 'e', 'r', 27, '[', '2', 'J', 10,
        'F', 'o', 'r', 'g', 'e', 'd',
    };
    const unsigned char* common_name_data = unsafe_text
        ? unsafe_common_name : common_name;
    int common_name_length = unsafe_text
        ? (int)sizeof(unsafe_common_name) : (int)(sizeof(common_name) - 1);
    if (!subject || X509_NAME_add_entry_by_txt(
            subject, "CN", MBSTRING_ASC, common_name_data,
            common_name_length, -1, 0) != 1 ||
        X509_set_issuer_name(cert, subject) != 1) {
        goto cleanup;
    }

    static const unsigned char dns_text[] = "certinfo.example.test";
    static const unsigned char unsafe_dns_text[] = {
        's', 'a', 'f', 'e', 27, '[', '2', 'J', 10,
        'f', 'o', 'r', 'g', 'e', 'd', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    };
    const unsigned char* dns_text_data = unsafe_text ? unsafe_dns_text : dns_text;
    int dns_text_length = unsafe_text
        ? (int)sizeof(unsafe_dns_text) : (int)(sizeof(dns_text) - 1);

    subject_alt_names = sk_GENERAL_NAME_new_null();
    dns_name = GENERAL_NAME_new();
    dns_value = ASN1_IA5STRING_new();
    if (!subject_alt_names || !dns_name || !dns_value ||
        ASN1_STRING_set(dns_value, dns_text_data, dns_text_length) != 1) {
        goto cleanup;
    }
    GENERAL_NAME_set0_value(dns_name, GEN_DNS, dns_value);
    dns_value = NULL;
    if (sk_GENERAL_NAME_push(subject_alt_names, dns_name) != 1) {
        goto cleanup;
    }
    dns_name = NULL;
    san_extension = X509V3_EXT_i2d(NID_subject_alt_name, 0, subject_alt_names);
    if (!san_extension || X509_add_ext(cert, san_extension, -1) != 1 ||
        X509_sign(cert, key, EVP_sha256()) <= 0) {
        goto cleanup;
    }

    output = fopen(path, "wb");
    if (!output || PEM_write_X509(output, cert) != 1) {
        goto cleanup;
    }
    if (fclose(output) != 0) {
        output = NULL;
        goto cleanup;
    }
    output = NULL;
    result = 0;

cleanup:
    if (result != 0) {
        ERR_print_errors_fp(stderr);
        if (output)
            fprintf(stderr, "Could not write test certificate to: %s\n", path);
    }
    if (output)
        fclose(output);
    X509_EXTENSION_free(san_extension);
    GENERAL_NAMES_free(subject_alt_names);
    GENERAL_NAME_free(dns_name);
    ASN1_IA5STRING_free(dns_value);
    X509_free(cert);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(key_context);
    return result;
}

int main(int argc, char* argv[]) {
    if ((argc != 3 && argc != 4) ||
        (argc == 4 && strcmp(argv[3], "unsafe") != 0)) {
        fprintf(stderr,
            "Usage: certinfo_test_cert <output_path> <valid|expired|future> [unsafe]\n");
        return 2;
    }
    return write_certificate(argv[1], argv[2], argc == 4);
}
