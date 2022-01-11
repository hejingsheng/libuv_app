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

SSLCertificate::SSLCertificate()
{

}

SSLCertificate::~SSLCertificate()
{

}

void SSLCertificate::init()
{
	RSA *rsa = NULL;
	int bits = 1024;
	ssl_pkey = EVP_PKEY_new();
	rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
	EVP_PKEY_assign_RSA(ssl_pkey, rsa);

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

std::string &SSLCertificate::get_fingerprint()
{
	return fingerprint;
}