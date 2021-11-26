#include "uv/include/ssl/Tls.hpp"

namespace tls
{
	TlsClient::TlsClient(uv::EventLoop *loop)
	{
		ctx_ = NULL;
		ssl_ = NULL;
		r_bio_ = NULL;
		w_bio_ = NULL;
		client_ = new uv::TcpClient(loop);
	}

	TlsClient::~TlsClient()
	{
		close();
		if (ctx_ != NULL)
		{
			SSL_CTX_free(ctx_);
			ctx_ = NULL;
		}
		if (ssl_ != NULL)
		{
			SSL_shutdown(ssl_);
			SSL_free(ssl_);
			ssl_ = NULL;
		}
		if (r_bio_ != NULL)
		{
			BIO_free(r_bio_);
			r_bio_ = NULL;
		}
		if (w_bio_ != NULL)
		{
			BIO_free(w_bio_);
			w_bio_ = NULL;
		}
		delete client_;
		client_ = nullptr;
	}

	int TlsClient::init()
	{
		int ret = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000L // v1.1.x
		SSL_library_init();
		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();
#else
#endif
		ctx_ = SSL_CTX_new(TLSv1_2_client_method());
		if (ctx_ == NULL) 
		{
			uv::LogWriter::Instance()->error("create ssl ctx fail no memery");
			ret = -1;
		}
		return ret;
	}

	int TlsClient::connect(uv::SocketAddr &addr)
	{
		int ret = 0;
		client_->setConnectStatusCallback(std::bind(&TlsClient::onConnectStatus, this, std::placeholders::_1));
		client_->setMessageCallback(std::bind(&TlsClient::onMessage, this, std::placeholders::_1, std::placeholders::_2));
		client_->connect(addr);
		return ret;
	}

	int TlsClient::close()
	{
		client_->close(nullptr);
	}

	int TlsClient::write(const char* buf, unsigned int size)
	{
		int ret = SSL_write(ssl_, buf, size);   // data�д����Ҫ���͵�����
		if (ret > 0) 
		{
			// д��socket
			send_bio_data();
		}
		else if (ret == 0) 
		{
			// ���ӹر��ˣ���
			uv::LogWriter::Instance()->warn("ssl write return 0 maybe close");
		}
		else 
		{
			// ��Ҫ��ȡ��д�����ݡ�
			int err = SSL_get_error(ssl_, ret);
			if (err == SSL_ERROR_WANT_READ) 
			{
				// ��read�ص��д�����ʵ���������Ҫ��ʱʲô����Ҫ����read�ص������ˡ�������
			}
			else if (err == SSL_ERROR_WANT_WRITE) 
			{
				send_bio_data();
			}
		}
		return ret;
	}

	void TlsClient::setConnectStatusCallback(TLSConnectStatusCallback callback)
	{
		connectCallback_ = callback;
	}

	void TlsClient::setMessageCallback(TLSMessageCallback callback)
	{
		messageCallback_ = callback;
	}

	void TlsClient::onConnectStatus(uv::TcpClient::ConnectStatus status)
	{
		int ret;
		if (status == uv::TcpClient::ConnectStatus::OnConnectSuccess)
		{
			ssl_ = SSL_new(ctx_);
			if (ssl_ == NULL)
			{
				uv::LogWriter::Instance()->warn("create ssl fail no memery");
				status_ = HANDSHAKE_FAIL;
				reportConnectStatus();
				return;
			}
			status_ = WAIT_HANDSHAKE;
			r_bio_ = BIO_new(BIO_s_mem());
			w_bio_ = BIO_new(BIO_s_mem());
			SSL_set_bio(ssl_, r_bio_, w_bio_);
			SSL_set_connect_state(ssl_);
			ret = SSL_connect(ssl_);
			send_bio_data();
			if (ret == 1)
			{
				status_ = HANDSHAKE_SUCC;
				reportConnectStatus();
			}
			else
			{
				int err = SSL_get_error(ssl_, ret);
				if (err == SSL_ERROR_WANT_WRITE)
				{
					send_bio_data();
				}
				else if (err == SSL_ERROR_WANT_READ) 
				{
					send_bio_data();
				}
				else 
				{
					//ERR_print_errors(errBio);
					uv::LogWriter::Instance()->error("ssl connect fail");
					status_ = HANDSHAKE_FAIL;
					reportConnectStatus();
				}
			}
		}
		else
		{
			status_ = HANDSHAKE_FAIL;
			reportConnectStatus();
		}
	}

	void TlsClient::onMessage(const char* data, ssize_t size)
	{
		if (size == UV_EOF) 
		{
			return;
		}
		else 
		{
			// ��ȡ���ݵ�BIO�С�buf�е������Ǽ������ݣ�����ŵ�BIO�У���openssl������롣
			BIO_write(r_bio_, data, size);
			if (!SSL_is_init_finished(ssl_)) 
			{
				// ���ǻ�û�����ssl�ĳ�ʼ���������������֡�
				int ret = SSL_connect(ssl_);
				send_bio_data();
				if (ret != 1) 
				{
					int err = SSL_get_error(ssl_, ret);
					status_ = WAIT_HANDSHAKE;
					if (err == SSL_ERROR_WANT_READ) 
					{
						// ��read�ص������ж�ȡ����
					}
					else if (err == SSL_ERROR_WANT_WRITE) 
					{
						send_bio_data();
					}
				}
				else 
				{
					// ������ɣ��������ݡ�
					status_ = HANDSHAKE_SUCC;
					reportConnectStatus();
					//send_data_after_handshake();
				}
			}
			else 
			{
				// ssl�Ѿ���ʼ������, ���ǿ��Դ�BIO�ж�ȡ�Ѿ����ܵ����ݡ�
				read_data_after_handshake();
			}
		}
	}

	int TlsClient::send_bio_data()
	{
		char buf[1024];
		int len;
		len = BIO_read(w_bio_, buf, sizeof(buf));
		if (len < 0)
		{
			return -1;
		}
		client_->writeInLoop(buf, len, nullptr);
	}

	void TlsClient::read_data_after_handshake()
	{
		char buf[1024] = {0};
		//memset(buf, '\0', sizeof(buf));
		int ret = SSL_read(ssl_, buf, sizeof(buf));
		if (ret < 0) 
		{
			int err = SSL_get_error(ssl_, ret);
			if (err == SSL_ERROR_WANT_READ) 
			{
				// ��read�ص������ж�ȡ����
			}
			else if (err == SSL_ERROR_WANT_WRITE) 
			{
				// ������Ҫд����write BIO�е����ݷ��ͳ�ȥ
				send_bio_data();
			}
		}
		else
		{
			if (messageCallback_)
			{
				messageCallback_(nullptr, buf, ret);
			}
		}
	}

	void TlsClient::reportConnectStatus()
	{
		if (connectCallback_)
		{
			if (status_ == HANDSHAKE_SUCC)
			{
				connectCallback_(uv::TcpClient::OnConnectSuccess);
			}
			else if (status_ == HANDSHAKE_FAIL)
			{
				connectCallback_(uv::TcpClient::OnConnnectFail);
			}
		}
	}
}