#include "ssl_manager.hpp"

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdint>
#include <stdexcept>
#include <string>

namespace ssl_mgr {

namespace {

/// Collect and return the latest OpenSSL error string.
std::string last_error() {
    char buf[256] = {};
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return std::string(buf);
}

/// RAII wrapper so we don't leak OpenSSL objects on early return.
template <typename T, void (*Free)(T*)>
struct Guard {
    T* ptr;
    explicit Guard(T* p) : ptr(p) {}
    ~Guard() { if (ptr) Free(ptr); }
    Guard(const Guard&)            = delete;
    Guard& operator=(const Guard&) = delete;
    operator T*() const { return ptr; }
};

using PkeyGuard = Guard<EVP_PKEY, EVP_PKEY_free>;
using X509Guard = Guard<X509,     X509_free>;
using ExtGuard  = Guard<X509_EXTENSION, X509_EXTENSION_free>;

} // anonymous namespace

namespace fs = std::filesystem;

void generate_self_signed_cert(
    const fs::path& cert_path,
    const fs::path& key_path,
    const std::string& cn,
    int days)
{
    PkeyGuard pkey{ EVP_RSA_gen(2048) };
    if (!pkey)
        throw std::runtime_error("EVP_RSA_gen failed: " + last_error());

    X509Guard cert{ X509_new() };
    if (!cert)
        throw std::runtime_error("X509_new failed");

    // Version 3 (value 2 = v3)
    X509_set_version(cert, 2);

    // Serial number - randomised to avoid SEC_ERROR_REUSED_ISSUER_AND_SERIAL
    {
        uint64_t serial_val = 0;
        RAND_bytes(reinterpret_cast<unsigned char*>(&serial_val), sizeof(serial_val));
        serial_val &= 0x7FFF'FFFF'FFFF'FFFFull; // keep MSB clear (positive ASN.1 integer)
        ASN1_INTEGER_set_uint64(X509_get_serialNumber(cert), serial_val);
    }

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert),  static_cast<long>(60 * 60 * 24) * days);

    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("US"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("Share2Me"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_set_issuer_name(cert, name);

    X509V3_CTX v3ctx;
    X509V3_set_ctx_nodb(&v3ctx);
    X509V3_set_ctx(&v3ctx, cert, cert, nullptr, nullptr, 0);

    std::string san = "DNS:" + cn;
    if (cn != "localhost") san += ",DNS:localhost";
    san += ",IP:127.0.0.1";

    {
        ExtGuard ext{
            X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_subject_alt_name, san.c_str())
        };
        if (ext) X509_add_ext(cert, ext, -1);
    }

    {
        ExtGuard ext{
            X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_basic_constraints, "CA:FALSE")
        };
        if (ext) X509_add_ext(cert, ext, -1);
    }

    {
        ExtGuard ext{
            X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_key_usage,
                                "digitalSignature,keyEncipherment")
        };
        if (ext) X509_add_ext(cert, ext, -1);
    }

    if (!X509_sign(cert, pkey, EVP_sha256()))
        throw std::runtime_error("X509_sign failed: " + last_error());

    {
        if (auto parent = key_path.parent_path(); !parent.empty())
            fs::create_directories(parent);

        FILE* f = fopen(key_path.string().c_str(), "wb");
        if (!f)
            throw std::runtime_error("Cannot open key file: " + key_path.string());

        PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(f);

        fs::permissions(key_path,
            fs::perms::owner_read | fs::perms::owner_write,
            fs::perm_options::replace);
    }

    {
        if (auto parent = cert_path.parent_path(); !parent.empty())
            fs::create_directories(parent);

        FILE* f = fopen(cert_path.string().c_str(), "wb");
        if (!f)
            throw std::runtime_error("Cannot open cert file: " + cert_path.string());

        PEM_write_X509(f, cert);
        fclose(f);
    }
}

bool needs_renewal(const fs::path& cert_path, int threshold_days) {
    if (!fs::exists(cert_path)) return true;

    FILE* f = fopen(cert_path.string().c_str(), "r");
    if (!f) return true;

    X509Guard cert{ PEM_read_X509(f, nullptr, nullptr, nullptr) };
    fclose(f);
    if (!cert) return true;

    int days_left = 0, secs_left = 0;
    ASN1_TIME_diff(&days_left, &secs_left, nullptr, X509_get0_notAfter(cert));
    return days_left < threshold_days;
}

bool ensure_certificates(
    const fs::path& cert_path,
    const fs::path& key_path,
    const std::string& cn,
    int renewal_threshold_days)
{
    if (fs::exists(cert_path) && fs::exists(key_path) &&
        !needs_renewal(cert_path, renewal_threshold_days))
    {
        return false;
    }

    generate_self_signed_cert(cert_path, key_path, cn);
    return true;
}

} // namespace ssl_mgr
