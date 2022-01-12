#ifndef _SSL_CERTIFICATE_H_
#define _SSL_CERTIFICATE_H_

extern "C"
{
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/x509.h"
}
#include <string>

class SSLCertificate
{
public:
	SSLCertificate(bool ecdsa = true);
	virtual ~SSLCertificate();

public:
	void init();
	X509* get_ssl_cert();
	EVP_PKEY* get_ssl_pkey();
	EC_KEY* get_ssl_eckey();
	std::string &get_fingerprint();

public:
	bool isecdsa;

private:
	X509 *ssl_cert;
	EVP_PKEY *ssl_pkey;
	EC_KEY *ssl_eckey;
	std::string fingerprint;
};

#endif