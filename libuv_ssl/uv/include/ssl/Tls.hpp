#ifndef _TLS_H_
#define _TLS_H_

extern "C"
{
#include "openssl/ssl.h"
#include "openssl/err.h"
}
#include "uv/include/TcpClient.hpp"
#include "uv/include/TcpServer.hpp"
#include "uv/include/TcpConnection.hpp"

namespace tls
{
	enum TlsStatus
	{
		HANDSHAKE_FAIL = -1,
		WAIT_HANDSHAKE = 0,
		HANDSHAKE_SUCC = 1,
	};

	using TLSConnectStatusCallback = std::function<void(uv::TcpClient::ConnectStatus)>;
	using TLSMessageCallback = std::function<void(uv::TcpConnectionPtr, const char*, ssize_t)>;

	class TlsClient
	{
	public:
		TlsClient(uv::EventLoop *loop);
		virtual ~TlsClient();

	public:
		int init();
		int connect(uv::SocketAddr &addr);
		int close();
		int write(const char* buf, unsigned int size);
		void setConnectStatusCallback(TLSConnectStatusCallback callback);
		void setMessageCallback(TLSMessageCallback callback);

	protected:
		void onConnectStatus(uv::TcpClient::ConnectStatus status);
		void onMessage(const char* data, ssize_t size);
		int send_bio_data();
		void read_data_after_handshake();

	private:
		void reportConnectStatus();

	private:
		SSL_CTX *ctx_;
		SSL *ssl_;
		BIO *r_bio_;
		BIO *w_bio_;
		uv::TcpClient *client_;
		TlsStatus status_;

		TLSConnectStatusCallback connectCallback_;
		TLSMessageCallback messageCallback_;
	};

}

#endif