#include <iostream>
#include <memory>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/x509v3.h>
#include "version.h"

static std::string ASN1_TIME_to_string(const ASN1_TIME* t) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return "BIO error";

    if (!ASN1_TIME_print(bio, t)) {
        BIO_free(bio);
        return "Invalid time";
    }

    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

static std::string ASN1_STRING_to_string(ASN1_STRING* str) {
    unsigned char* utf8 = nullptr;
    int len = ASN1_STRING_to_UTF8(&utf8, str);
    if (len < 0) return {};

    std::string out(reinterpret_cast<char*>(utf8), len);
    OPENSSL_free(utf8);
    return out;
}

static void processCertificate(X509* cert, int index) {
    X509_NAME* subject = X509_get_subject_name(cert);
    int cn_idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);

    std::cout << "#" << index << " - Common Name (CN): ";

    if (cn_idx >= 0) {
        X509_NAME_ENTRY* e = X509_NAME_get_entry(subject, cn_idx);
        ASN1_STRING* cn = X509_NAME_ENTRY_get_data(e);
        std::cout << "\033[1m" << ASN1_STRING_to_string(cn) << "\033[0m\n";
    } else {
        std::cout << "\033[1mN/A\033[0m\n";
    }

    auto not_before = X509_get0_notBefore(cert);
    auto not_after  = X509_get0_notAfter(cert);

    std::cout << "\t\033[33mValid from:\033[0m " << ASN1_TIME_to_string(not_before) << "\n";

    auto na = ASN1_TIME_to_string(not_after);
    if (X509_cmp_current_time(not_after) < 0)
        std::cout << "\t\033[1;31mValid until:\033[0m \033[1;31m" << na << " (Expired)\033[0m\n";
    else
        std::cout << "\t\033[33mValid until:\033[0m " << na << "\n";

    GENERAL_NAMES* names = (GENERAL_NAMES*)X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
    if (names) {
        int count = sk_GENERAL_NAME_num(names);
        for (int i = 0; i < count; i++) {
            GENERAL_NAME* n = sk_GENERAL_NAME_value(names, i);
            if (n->type == GEN_DNS)
                std::cout << "\tSAN: " << ASN1_STRING_to_string(n->d.dNSName) << "\n";
        }
        GENERAL_NAMES_free(names);
    }
}

int main(int argc, char* argv[]) {
    const char* prog = argv[0];

    if (argc == 2 && std::string(argv[1]) == "--help") {
        std::cout << "Usage: " << prog << " <path_to_pem_bundle>\n";
        std::cout << "Options:\n";
        std::cout << "  --help     Show help\n";
        std::cout << "  --version  Show version\n";
        return 0;
    }

    if (argc == 2 && std::string(argv[1]) == "--version") {
        std::cout << "certinfo_cpp version " << CERTINFO_VERSION << "\n";
        return 0;
    }

    if (argc != 2) {
        std::cout << "Usage: " << prog << " <path_to_pem_bundle>\n";
        std::cout << "Options:\n";
        std::cout << "  --help     Show help\n";
        std::cout << "  --version  Show version\n";
        return 1;
    }

    const char* path = argv[1];

    FILE* f = fopen(path, "r");
    if (!f) {
        std::cerr << "Cannot open: " << path << "\n";
        return 1;
    }

    X509* cert;
    int index = 1;

    while ((cert = PEM_read_X509(f, nullptr, nullptr, nullptr))) {
        processCertificate(cert, index++);
        X509_free(cert);
    }

    fclose(f);
    return 0;
}
