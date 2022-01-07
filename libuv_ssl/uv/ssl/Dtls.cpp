/*
Author: hejingsheng@qq.com

Date: 2021/11/26
*/
#include "uv/include/ssl/Dtls.hpp"
#include "uv/include/LogWriter.hpp"

namespace Dtls
{

	/* DTLS alert callback */
	void uv_dtls_callback(const SSL *ssl, int where, int ret) 
	{
		/* We only care about alerts */
		if (!(where & SSL_CB_ALERT)) 
		{
			return;
		}
		DtlsBase *dtls = (DtlsBase*)SSL_get_ex_data(ssl, 0);
		if (!dtls) 
		{
			return;
		}
		std::string alert_type = SSL_alert_type_string_long(ret);
		std::string alert_desc = SSL_alert_desc_string_long(ret);
		uv::LogWriter::Instance()->error("dtls alert");
		dtls->alertCallback(alert_type, alert_desc);
		return;
	}

	int uv_verify_callback(int isOk, X509_STORE_CTX *ctx)
	{
		// Always OK, we don't check the certificate of client,
		// because we allow client self-sign certificate.
		if (isOk == 1)
		{
			// check success
		}
		else
		{
			// isOk == 0  check fail
		}
		return 1;
	}

	DtlsBase::DtlsBase(IDtlsCallback *callback) : dtlsCallback_(callback)
	{
		ctx_ = NULL;
		ssl_ = NULL;
		rbio_ = NULL;
		wbio_ = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L // v1.1.x
		//SSL初库始化
		SSL_library_init();
		//载入所有SSL算法
		OpenSSL_add_ssl_algorithms();
		//载入所有错误信息
		SSL_load_error_strings();
#else
#endif
		ssl_certificate.init();
	}

	DtlsBase::~DtlsBase()
	{
		if (ctx_ != NULL)
		{
			SSL_CTX_free(ctx_);
			ctx_ = NULL;
		}
		if (ssl_ != NULL)
		{
			SSL_free(ssl_);
			ssl_ = NULL;
		}
		dtlsCallback_ = nullptr;
	}

	int DtlsBase::init(std::string cert, std::string key, DtlsRole role)
	{
		int ret = 0;
		if (role == DtlsRoleClient)
		{
			ctx_ = SSL_CTX_new(DTLS_client_method());
			if (ctx_ == NULL)
			{
				uv::LogWriter::Instance()->error("create ssl ctx fail no memery");
				return -1;
			}
			SSL_CTX_set_cipher_list(ctx_, "ALL");
			//加载证书和私钥
			if (0 == SSL_CTX_use_certificate(ctx_, ssl_certificate.get_ssl_cert()))
			{
				ERR_print_errors_fp(stderr);
				return -1;
			}
			if (0 == SSL_CTX_use_PrivateKey(ctx_, ssl_certificate.get_ssl_pkey()))
			{
				ERR_print_errors_fp(stderr);
				return -1;
			}
			if (!SSL_CTX_check_private_key(ctx_))
			{
				uv::LogWriter::Instance()->error("Private key does not match the certificate public key");
				return -1;
			}
		}
		else if (role == DtlsRoleServer)
		{
			ctx_ = SSL_CTX_new(DTLS_server_method());
			if (ctx_ == NULL)
			{
				uv::LogWriter::Instance()->error("create ssl ctx fail no memery");
				return -1;
			}
			ret = SSL_CTX_set_cipher_list(ctx_, "ALL");
			if (ret != 1)
			{
				uv::LogWriter::Instance()->error("SSL_CTX_set_cipher_list fail");
				return -1;
			}
			//加载证书和私钥
			if (0 == SSL_CTX_use_certificate_file(ctx_, cert.c_str(), SSL_FILETYPE_PEM))
			{
				ERR_print_errors_fp(stderr);
				return -1;
			}
			if (0 == SSL_CTX_use_PrivateKey_file(ctx_, key.c_str(), SSL_FILETYPE_PEM))
			{
				ERR_print_errors_fp(stderr);
				return -1;
			}
			if (!SSL_CTX_check_private_key(ctx_))
			{
				uv::LogWriter::Instance()->error("Private key does not match the certificate public key");
				return -1;
			}
		}
		else
		{
			return -1;
		}
		SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, uv_verify_callback);
		SSL_CTX_set_verify_depth(ctx_, 4);
		SSL_CTX_set_read_ahead(ctx_, 1);

		ssl_ = SSL_new(ctx_);
		if (ssl_ == NULL)
		{
			uv::LogWriter::Instance()->warn("create ssl fail no memery");
			return -1;
		}

		SSL_set_ex_data(ssl_, 0, this);
		SSL_set_info_callback(ssl_, uv_dtls_callback);
		SSL_set_options(ssl_, SSL_OP_NO_QUERY_MTU);
		SSL_set_mtu(ssl_, 1500);

		rbio_ = BIO_new(BIO_s_mem());
		wbio_ = BIO_new(BIO_s_mem());
		SSL_set_bio(ssl_, rbio_, wbio_);
		return 0;
	}

	void DtlsBase::writeData(const char *buf, unsigned int size)
	{
		int err;
		char *data = NULL;
		int len;
		SSL_write(ssl_, buf, size);
		len = BIO_get_mem_data(wbio_, &data);
		if (len > 0 && data != NULL)
		{
			if (dtlsCallback_)
			{
				dtlsCallback_->onDtlsSendData(data, len);
			}
			BIO_reset(wbio_);
		}
		else
		{

		}
	}

	void DtlsBase::alertCallback(std::string type, std::string desc)
	{
		if (dtlsCallback_)
		{
			dtlsCallback_->onDtlsAlert(type, desc);
		}
	}

	void DtlsBase::checkRemoteCertificate(std::string &fingerprint)
	{
		X509 *cert;
		unsigned int rsize;
		unsigned char rfingerprint[EVP_MAX_MD_SIZE] = { 0 };
		char remote_fingerprint[160] = { 0 };
		char *rfp = (char *)&remote_fingerprint;
		int ret;

		if (ssl_ != nullptr)
		{
			cert = SSL_get_peer_certificate(ssl_);
			if (cert != nullptr)
			{
				ret = X509_cmp_current_time(X509_get_notAfter(cert));
				if (ret < 0)
				{
					alertCallback("warning", "certificate expired");
				}
				X509_digest(cert, EVP_sha256(), (unsigned char *)rfingerprint, &rsize);
				X509_free(cert);
				cert = NULL;
				for (unsigned int i = 0; i < rsize; i++)
				{
					snprintf(rfp, 4, "%.2X:", rfingerprint[i]);
					rfp += 3;
				}
				*(rfp - 1) = 0;
				fingerprint.assign(remote_fingerprint, strlen(remote_fingerprint));
			}
		}
	}

	void DtlsBase::send_bio_data()
	{
		char *data = NULL;
		int len;

		len = BIO_get_mem_data(wbio_, &data);
		if (data != NULL && len > 0)
		{
			BIO_reset(rbio_);
			if (dtlsCallback_)
			{
				dtlsCallback_->onDtlsSendData(data, len);
			}
			BIO_reset(wbio_);
		}
	}

	DtlsServer::DtlsServer(IDtlsCallback *callback) : DtlsBase(callback)
	{
		dtlsStatus_ = DtlsStateInit;
	}

	DtlsServer::~DtlsServer()
	{

	}

	int DtlsServer::init(std::string cert, std::string key, DtlsRole role)
	{
		int ret;
		ret = DtlsBase::init(cert, key, role);

		if (ret < 0)
		{
			uv::LogWriter::Instance()->error("dtls server init fail");
			return -1;
		}

		SSL_set_accept_state(ssl_);
		return 0;
	}

	void DtlsServer::onMessage(const char *buf, unsigned int size)
	{
		int len;
		int r0, r1;
		len = BIO_write(rbio_, buf, size);
		if (!dtlsConnect_)
		{
			r0 = SSL_do_handshake(ssl_);
			r1 = SSL_get_error(ssl_, r0);
			if (r0 != 1)
			{
				send_bio_data();
				dtlsStatus_ = DtlsStateServerHello;
			}
			else if (r0 == 1)
			{
				send_bio_data();
				uv::LogWriter::Instance()->info("DTLS connect success");
				if (r1 == SSL_ERROR_NONE)
				{
					dtlsConnect_ = true;
					dtlsStatus_ = DtlsStateServerDone;
					if (dtlsCallback_)
					{
						dtlsCallback_->onDtlsHandShakeDone();
					}
				}
			}
		}
		else
		{
			int ret;
			ret = SSL_read(ssl_, (void*)buf, size);
			if (ret <= 0)
			{
				int err = SSL_get_error(ssl_, ret);
				if (err == SSL_ERROR_WANT_READ)
				{
					// 在read回调函数中读取数据
				}
				else if (err == SSL_ERROR_WANT_WRITE)
				{
					send_bio_data();
				}
				else
				{
					// closed
				}
			}
			else
			{
				if (dtlsCallback_)
				{
					dtlsCallback_->onDtlsRecvData(buf, ret);
				}
			}
		}
	}

	int DtlsServer::startHandShake()
	{
		// wait client send handshake request
		return 0;
	}

	DtlsClient::DtlsClient(uv::EventLoop *loop, IDtlsCallback *callback) : DtlsBase(callback)
	{
		dtlsConnect_ = false;
		dtlsStatus_ = DtlsStateInit;
		retryTime = 0;
		arqTimer_ = new uv::Timer(loop, 100, 0, std::bind(&DtlsClient::startRetransmitTimer, this));
	}

	DtlsClient::~DtlsClient()
	{
		if (arqTimer_)
		{
			delete arqTimer_;
			arqTimer_ = nullptr;
		}
	}

	int DtlsClient::init(std::string cert, std::string key, DtlsRole role)
	{
		int ret;
		ret = DtlsBase::init(cert, key, role);
		if (ret < 0)
		{
			uv::LogWriter::Instance()->error("dtls client init fail");
			return -1;
		}

		SSL_set_connect_state(ssl_);
		SSL_set_max_send_fragment(ssl_, 1500);
		return ret;
	}

	int DtlsClient::startHandShake()
	{
		int ret;

		ret = SSL_do_handshake(ssl_);
		if (ret == 1)
		{
			uv::LogWriter::Instance()->warn("connect success");
			return 0;
		}
		else
		{
			int err = SSL_get_error(ssl_, ret);
			if (err == SSL_ERROR_WANT_WRITE)
			{
				ret = 1;
			}
			else if (err == SSL_ERROR_WANT_READ)
			{
				send_bio_data();
				dtlsStatus_ = DtlsStateClientHello;
				arqTimer_->start();
				ret = 1;
			}
			else
			{
				uv::LogWriter::Instance()->error("ssl connect fail");
				ret = -1;
			}
		}
		return ret;
	}

	void DtlsClient::onMessage(const char *buf, unsigned int size)
	{
		int len;
		int r0, r1;
		len = BIO_write(rbio_, buf, size);
		if (!dtlsConnect_)
		{
			r0 = SSL_do_handshake(ssl_);
			r1 = SSL_get_error(ssl_, r0);
			if (r0 != 1)
			{
				if (r1 == SSL_ERROR_WANT_WRITE)
				{

				}
				else if (r1 == SSL_ERROR_WANT_READ)
				{
					send_bio_data();
				}
				if (dtlsStatus_ == DtlsStateClientHello)
				{
					dtlsStatus_ = DtlsStateClientCertificate;
				}
				arqTimer_->stop();
				arqTimer_->setTimeout(100);
				arqTimer_->start();
			}
			else if (r0 == 1)
			{
				uv::LogWriter::Instance()->info("DTLS connect success");
				dtlsConnect_ = true;
				dtlsStatus_ = DtlsStateClientDone;
				//close arq timer
				arqTimer_->close(nullptr);
				if (dtlsCallback_)
				{
					dtlsCallback_->onDtlsHandShakeDone();
				}
			}
		}
		else
		{
			int ret;
			ret = SSL_read(ssl_, (void*)buf, size);
			if (ret <= 0)
			{
				int err = SSL_get_error(ssl_, ret);
				if (err == SSL_ERROR_WANT_READ)
				{
					// 在read回调函数中读取数据
				}
				else if (err == SSL_ERROR_WANT_WRITE)
				{
					send_bio_data();
				}
				else
				{
					// closed
				}
			}
			else
			{
				if (dtlsCallback_)
				{
					dtlsCallback_->onDtlsRecvData(buf, ret);
					std::string f;
					//getRemoteFingerprint(f);
					checkRemoteCertificate(f);
				}
			}
		}
	}

	void DtlsClient::startRetransmitTimer()
	{
		if (dtlsStatus_ != DtlsStateClientCertificate && dtlsStatus_ != DtlsStateClientHello)
		{
			return;
		}
		if (retryTime >= 10)
		{
			uv::LogWriter::Instance()->error("try 10 times not success close socket");
			arqTimer_->stop();
			retryTime = 0;
			return;
		}

		int r0 = 0;
		int r1;
		struct timeval to = { 0 };
		r0 = DTLSv1_get_timeout(ssl_, &to);
		if (r0 == 0)
		{
			// get time out fail
			arqTimer_->stop();
			arqTimer_->start();
			return;
		}
		uint64_t timeout = to.tv_sec * 1000 + to.tv_usec / 1000;
		if (timeout == 0)
		{
			r0 = BIO_reset(wbio_); 
			int r1 = SSL_get_error(ssl_, r0);
			if (r0 != 1) {
				uv::LogWriter::Instance()->error("Bio reset error");
				return;
			}
			r0 = DTLSv1_handle_timeout(ssl_);
			send_bio_data();
		}
		else
		{
			arqTimer_->setTimeout(timeout);
		}
		arqTimer_->stop();
		arqTimer_->start();
		retryTime++;
	}

}