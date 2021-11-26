/*
Author: hejingsheng@qq.com

Date: 2021/11/26
*/
#include "uv/include/ssl/Dtls.hpp"
#include "uv/include/LogWriter.hpp"

namespace Dtls
{
	DtlsBase::DtlsBase(uv::EventLoop *loop)
	{
		ctx_ = NULL;
		ssl_ = NULL;
		rbio_ = NULL;
		wbio_ = NULL;

		udpSocekt_ = new uv::Udp(loop);
#if OPENSSL_VERSION_NUMBER < 0x10100000L // v1.1.x
		//SSL初库始化
		SSL_library_init();
		//载入所有SSL算法
		OpenSSL_add_ssl_algorithms();
		//载入所有错误信息
		SSL_load_error_strings();
#else
#endif
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
		if (udpSocekt_)
		{
			delete udpSocekt_;
			udpSocekt_ = nullptr;
		}
	}

	int DtlsBase::init(std::string cert, std::string key)
	{
		
	}

	void DtlsBase::onMessage(uv::SocketAddr &addr, const char *buf, unsigned int size)
	{
		return;
	}

	DtlsServer::DtlsServer(uv::EventLoop *loop) : DtlsBase(loop)
	{

	}

	DtlsServer::~DtlsServer()
	{

	}

	DtlsClient::DtlsClient(uv::EventLoop *loop, uv::SocketAddr &addr) : DtlsBase(loop)
	{
		udpSocekt_->setMessageCallback(std::bind(&DtlsClient::onMessage, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
		udpSocekt_->bindAndRead(addr);
		addr_ = new uv::SocketAddr(addr.Addr(), addr.Ipv());
		dtlsConnect_ = false;
	}

	DtlsClient::~DtlsClient()
	{
		//delete udpSocekt_;
		delete addr_;
	}

	int DtlsClient::init(std::string cert, std::string key)
	{
		DtlsBase::init(cert, key);
		int ret = 0;
		ctx_ = SSL_CTX_new(DTLS_client_method());
		if (ctx_ == NULL)
		{
			uv::LogWriter::Instance()->error("create ssl ctx fail no memery");
			return -1;
		}
		SSL_CTX_clear_mode(ctx_, SSL_MODE_AUTO_RETRY);
		
		ssl_ = SSL_new(ctx_);
		if (ssl_ == NULL)
		{
			uv::LogWriter::Instance()->warn("create ssl fail no memery");
			return -1;
		}
		rbio_ = BIO_new(BIO_s_mem());
		wbio_ = BIO_new(BIO_s_mem());
		SSL_set_bio(ssl_, rbio_, wbio_);
		SSL_set_connect_state(ssl_);
		ret = SSL_connect(ssl_);
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
				ret = 1;
			}
			else
			{
				//ERR_print_errors(errBio);
				uv::LogWriter::Instance()->error("ssl connect fail");
				ret = -1;
			}
		}
		return ret;
	}

	void DtlsClient::onMessage(uv::SocketAddr &addr, const char *buf, unsigned int size)
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
			}
			else if (r0 == 1)
			{
				uv::LogWriter::Instance()->info("DTLS connect success");
				dtlsConnect_ = true;
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
				
			}
		}
	}

	void DtlsClient::send_bio_data()
	{
		char *data = NULL;
		int len;

		len = BIO_get_mem_data(wbio_, &data);
		if (data != NULL && len > 0)
		{
			BIO_reset(rbio_);
			uv::SocketAddr addr("192.168.0.200", 8443);
			udpSocekt_->send(addr, data, len);
			BIO_reset(wbio_);
		}
	}

}