/*
Author: hejingsheng@qq.com

Date: 2021/11/26
*/
#ifndef _TLS_H_
#define _TLS_H_

extern "C"
{
#include "openssl/ssl.h"
#include "openssl/err.h"
}
#include "uv/include/Udp.hpp"

namespace Dtls
{
	using DtlsMessageCallback = std::function<void(uv::SocketAddr&, const char*, unsigned)>;
	using DtlsHandShakeDone = std::function<void(void)>;

	class DtlsBase
	{
	public:
		DtlsBase(uv::EventLoop *loop);
		virtual ~DtlsBase();

	protected:
		virtual int init(std::string cert, std::string key);
		virtual void onMessage(uv::SocketAddr &addr, const char *buf, unsigned int size);

	protected:
		SSL_CTX *ctx_;
		SSL *ssl_;
		BIO *rbio_;
		BIO *wbio_;

		uv::Udp *udpSocekt_;
	};

	class DtlsServer : public DtlsBase
	{
	public:
		DtlsServer(uv::EventLoop *loop);
		virtual ~DtlsServer();

	private:

	};

	class DtlsClient: public DtlsBase
	{
	public:
		DtlsClient(uv::EventLoop *loop, uv::SocketAddr &addr);
		virtual ~DtlsClient();

	public:
		virtual int init(std::string cert, std::string key);
		virtual void onMessage(uv::SocketAddr &addr, const char *buf, unsigned int size);

	public:
		void write(const char *buf, unsigned int size);
		void close();
		void setMessageCallback(DtlsMessageCallback callback);
		void setDtlsHandShakeDone(DtlsHandShakeDone callback);

	private:
		void send_bio_data();

	private:
		uv::SocketAddr *addr_;
		bool dtlsConnect_;

		DtlsHandShakeDone dtlsHandShakeDone_;
		DtlsMessageCallback dtlsMessageCallback_;
	};

}

#endif