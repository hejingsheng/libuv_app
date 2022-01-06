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
#include "uv/include/Timer.hpp"
#include "uv/include/ssl/SSLCertificate.hpp"

namespace Dtls
{

	enum DtlsState {
		DtlsStateInit, // Start.
		DtlsStateClientHello, // Should start ARQ thread.
		DtlsStateServerHello, // We are in the first ARQ state.
		DtlsStateClientCertificate, // Should start ARQ thread again.
		DtlsStateServerDone, // We are in the second ARQ state.
		DtlsStateClientDone, // Done.
	};

	enum DtlsRole {
		DtlsRoleServer,
		DtlsRoleClient,
	};

	class IDtlsCallback
	{
	public:
		virtual void onDtlsHandShakeDone() = 0;
		virtual void onDtlsRecvData(const char *data, unsigned int len) = 0;
		virtual void onDtlsSendData(const char *data, unsigned int len) = 0;
		virtual void onDtlsAlert(std::string type, std::string desc) = 0;

		virtual ~IDtlsCallback() = default;
	};

	class DtlsBase
	{
	public:
		DtlsBase(IDtlsCallback *callback);
		virtual ~DtlsBase();

	public:
		virtual int init(std::string cert, std::string key, DtlsRole role);
		virtual void onMessage(const char *buf, unsigned int size) = 0;
		virtual int startHandShake() = 0;
		virtual void writeData(const char *buf, unsigned int size);
		virtual void alertCallback(std::string type, std::string desc);

	protected:
		void send_bio_data();

	protected:
		SSL_CTX *ctx_;
		SSL *ssl_;
		BIO *rbio_;
		BIO *wbio_;

		IDtlsCallback *dtlsCallback_;
		SSLCertificate ssl_certificate;
	};

	class DtlsServer : public DtlsBase
	{
	public:
		DtlsServer(IDtlsCallback *callback);
		virtual ~DtlsServer();

	public:
		virtual int init(std::string cert, std::string key, DtlsRole role);
		virtual void onMessage(const char *buf, unsigned int size);
		virtual int startHandShake();

	private:
		bool dtlsConnect_ = false;
		DtlsState dtlsStatus_;

	};

	class DtlsClient: public DtlsBase
	{
	public:
		DtlsClient(uv::EventLoop *loop, IDtlsCallback *callback);
		virtual ~DtlsClient();

	public:
		virtual int init(std::string cert, std::string key, DtlsRole role);
		virtual void onMessage(const char *buf, unsigned int size);
		virtual int startHandShake();

	private:
		void startRetransmitTimer();

	private:
		bool dtlsConnect_;
		DtlsState dtlsStatus_;
		int retryTime;

		uv::Timer *arqTimer_;
	};

}

#endif