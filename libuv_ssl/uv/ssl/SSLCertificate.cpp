#include "uv/include/ssl/SSLCertificate.hpp"
#include <sys/time.h>
#include "string.h"

static int getRandom()
{
	timeval now;
	uint64_t time;
	gettimeofday(&now, NULL);
	time = ((int64_t)now.tv_sec) * 1000 * 1000 + (int64_t)now.tv_usec;
	srand(time);

	return (int)rand();
}

SSLCertificate::SSLCertificate(bool ecdsa) : isecdsa(ecdsa)
{
	ssl_cert = NULL;
	ssl_pkey = NULL;
	ssl_eckey = NULL;
}

SSLCertificate::~SSLCertificate()
{
	if (ssl_cert != NULL)
		X509_free(ssl_cert);
	if (ssl_pkey != NULL)
		EVP_PKEY_free(ssl_pkey);
	if (ssl_eckey != NULL)
		EC_KEY_free(ssl_eckey);
}

void SSLCertificate::init()
{
	RSA *rsa = NULL;
	int bits = 1024;
	ssl_pkey = EVP_PKEY_new();

	if (isecdsa)
	{
		ssl_eckey = EC_KEY_new();
		EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
#if OPENSSL_VERSION_NUMBER < 0x10100000L // v1.1.x
		// For openssl 1.0, we must set the group parameters, so that cert is ok.
		// @see https://github.com/monero-project/monero/blob/master/contrib/epee/src/net_ssl.cpp#L225
		EC_GROUP_set_asn1_flag(ecgroup, OPENSSL_EC_NAMED_CURVE);
#endif
		EC_KEY_set_group(ssl_eckey, group);
		EC_KEY_generate_key(ssl_eckey);
		EVP_PKEY_set1_EC_KEY(ssl_pkey, ssl_eckey);
		EC_GROUP_free(group);
	}
	if (!isecdsa)
	{
#if OPENSSL_VERSION_NUMBER < 0x10002000L // v1.0.2
		rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
#else
		rsa = RSA_new();
		BIGNUM *bn = BN_new();
		BN_set_word(bn, RSA_F4);
		RSA_generate_key_ex(rsa, bits, bn, NULL);
		BN_free(bn);
#endif
		EVP_PKEY_assign_RSA(ssl_pkey, rsa);
		RSA_free(rsa);
	}
	// create certificate
	ssl_cert = X509_new();
	X509_NAME* subject = X509_NAME_new();

	int serial = getRandom();
	ASN1_INTEGER_set(X509_get_serialNumber(ssl_cert), serial);

	const std::string aor = "libuv_ssl.net";
	X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (unsigned char *)aor.data(), aor.size(), -1, 0);

	X509_set_issuer_name(ssl_cert, subject);
	X509_set_subject_name(ssl_cert, subject);

	int expire_day = 365;
	const long cert_duration = 60 * 60 * 24 * expire_day;
	X509_gmtime_adj(X509_get_notBefore(ssl_cert), 0);
	X509_gmtime_adj(X509_get_notAfter(ssl_cert), cert_duration);

	X509_set_version(ssl_cert, 2);
	X509_set_pubkey(ssl_cert, ssl_pkey);
	X509_sign(ssl_cert, ssl_pkey, EVP_sha1());

	X509_NAME_free(subject);

	// create  fingerprint
	char fp[100] = { 0 };
	char *p = fp;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int n = 0;

	X509_digest(ssl_cert, EVP_sha256(), md, &n);

	for (unsigned int i = 0; i < n; i++, ++p) {
		sprintf(p, "%02X", md[i]);
		p += 2;

		if (i < (n - 1)) {
			*p = ':';
		}
		else {
			*p = '\0';
		}
	}
	fingerprint.assign(fp, strlen(fp));
}

X509* SSLCertificate::get_ssl_cert()
{
	return ssl_cert;
}

EVP_PKEY* SSLCertificate::get_ssl_pkey()
{
	return ssl_pkey;
}

EC_KEY* SSLCertificate::get_ssl_eckey()
{
	return ssl_eckey;
}

std::string &SSLCertificate::get_fingerprint()
{
	return fingerprint;
}