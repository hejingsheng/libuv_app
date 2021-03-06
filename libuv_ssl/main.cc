#include <iostream>
#include "string.h"
#include "uv/include/uv11.hpp"
#include "uv/include/ssl/Dtls.hpp"
#include "uv/include/Timer.hpp"
#include "uv/include/UdpListener.hpp"
#include "app/stun.h"
#include "uv/include/websocket/WebsocketApp.hpp"
#include "unistd.h"

#if 0
#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <curses.h>
#define MSGLENGTH 1024
#define PORT 8443
#define CACERT "./private/ca.crt"
#define SVRCERTF "server.crt"
#define SVRKEYF "server.key"
#define ADDRESS "0.0.0.0"
int main()
{
	int sock;
	char buf[MSGLENGTH];
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;
	//SSL初库始化
	SSL_library_init();
	//载入所有SSL算法
	OpenSSL_add_ssl_algorithms();
	//载入所有错误信息
	SSL_load_error_strings();
	meth = (SSL_METHOD *)TLSv1_2_method();
	ctx = SSL_CTX_new(meth);
	if (NULL == ctx)
		exit(1);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	//SSL_CTX_load_verify_locations(ctx, CACERT, NULL);
	//加载证书和私钥
	if (0 == SSL_CTX_use_certificate_file(ctx, SVRCERTF, SSL_FILETYPE_PEM))
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (0 == SSL_CTX_use_PrivateKey_file(ctx, SVRKEYF, SSL_FILETYPE_PEM))
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!SSL_CTX_check_private_key(ctx))
	{
		printf("Private key does not match the certificate public key\n");
		exit(1);
	}
	//SSL_CTX_set_cipher_list(ctx, "RC4-MD5");
	SSL_CTX_set_cipher_list(ctx, "ALL");
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
	printf("Begin tcp socket...\n");
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1)
	{
		printf("SOCKET error! \n");
		return 0;
	}
	//准备通信地址和端口号
	struct sockaddr_in addr;
	memset(&addr, '\0', sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT); /* Server Port number */
	//addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_addr.s_addr = inet_addr(ADDRESS);
	//绑定地址和端口号
	int nResult = bind(sock, (struct sockaddr *) &addr, sizeof(addr));
	if (nResult == -1)
	{
		printf("bind socket error\n");
		return 0;
	}
	printf("server start successfully,port:%d\nwaiting for connections\n", PORT);
	struct sockaddr_in sa_cli;
	//设置最大连接数
	int err = listen(sock, 5);
	if (-1 == err)
		exit(1);
	int client_len = sizeof(sa_cli);
	//等待客户端连接
	int ss = accept(sock, (struct sockaddr *) &sa_cli, (socklen_t*)&client_len);
	if (ss == -1)
	{
		exit(1);
	}
	close(sock);
	printf("Connection from %d, port %d\n", sa_cli.sin_addr.s_addr, sa_cli.sin_port);
	ssl = SSL_new(ctx);
	if (NULL == ssl)
		exit(1);
#if 1
	BIO *rbio_;
	BIO *wbio_;
	rbio_ = BIO_new(BIO_s_mem());
	if (rbio_ == NULL)
	{
		exit(1);
	}
	wbio_ = BIO_new(BIO_s_mem());
	if (wbio_ == NULL)
	{
		exit(1);
	}
	SSL_set_bio(ssl, rbio_, wbio_);
	SSL_set_accept_state(ssl);
	SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
	while (1)
	{
		int r0, r1;
		err = read(ss, buf, sizeof(buf));
		BIO_write(rbio_, buf, err);
		r0 = SSL_do_handshake(ssl);
		r1 = SSL_get_error(ssl, r0);
		if (r0 != 1)
		{
			switch (r1)
			{
			case SSL_ERROR_NONE: //0
			case SSL_ERROR_SSL:  // 1
				ERR_print_errors_fp(stderr);
				//don't break, flush data first
			case SSL_ERROR_WANT_READ: // 2
			case SSL_ERROR_WANT_WRITE: // 3
			case SSL_ERROR_WANT_X509_LOOKUP:  // 4
			{
				char *data = NULL;
				int len;

				len = BIO_get_mem_data(wbio_, &data);
				BIO_reset(rbio_);
				if (data != NULL && len > 0)
				{
					write(ss, data, len);
					BIO_reset(wbio_);
				}
			}
			break;
			case SSL_ERROR_ZERO_RETURN: // 5
			case SSL_ERROR_SYSCALL: //6
			case SSL_ERROR_WANT_CONNECT: //7
			case SSL_ERROR_WANT_ACCEPT: //8
				ERR_print_errors_fp(stderr);
			default:
				break;
			}
		}
		if (r0 == 1)
		{
			char *data = NULL;
			int len;

			len = BIO_get_mem_data(wbio_, &data);
			BIO_reset(rbio_);
			if (data != NULL && len > 0)
			{
				write(ss, data, len);
				BIO_reset(wbio_);
			}
			break;
		}
	}
#else
	if (0 == SSL_set_fd(ssl, ss))
	{
		printf("Attach to Line fail!\n");
		exit(1);
	}
	int k = SSL_accept(ssl);
	if (0 == k)
	{
		printf("%d/n", k);
		printf("SSL connect fail!\n");
		exit(1);
	}

#endif
	SSL_write(ssl, "Server is connect to you!\n", strlen("Server is connect to you!\n"));
	err = BIO_read(wbio_, buf, sizeof(buf));
	write(ss, buf, err);
	printf("Listen to the client: \n");
	while (1)
	{
		char buff[1024];
		err = read(ss, buf, sizeof(buf));
		err = BIO_write(rbio_, buf, err);
		err = SSL_read(ssl, buff, sizeof(buff));
		buff[err] = '\0';
		printf("%s\n", buff);
		SSL_write(ssl, "recv data\n", strlen("recv data\n"));
		err = BIO_read(wbio_, buf, sizeof(buf));
		write(ss, buf, err);
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	getch();
	return 0;
}
#else
uv::SocketAddr *global_addr;
class testClass : public Dtls::IDtlsCallback, public udpListen::IUdpListenCallback, public uv_app::IStunCallback
{
public:
	testClass(uv::Udp *udp)
	{
		udpSocket = udp;
	}

	~testClass()
	{

	}

	void onDtlsHandShakeDone()
	{

	}

	void onDtlsRecvData(const char *data, unsigned int len)
	{

	}

	void onDtlsSendData(const char *data, unsigned int len)
	{
		uv::SocketAddr addr("192.168.0.200", 8443);
		udpSocket->send(addr, data, len);
		//udpSocket->send(*global_addr, data, len);
	}

	void onDtlsAlert(std::string type, std::string desc)
	{

	}

	void onUdpMsgRecv(uv::SocketAddr &addr, const char *data, unsigned int len)
	{
		std::cout << "recv:" << data << std::endl;
	}

	void onStunFail(uv_app::StunCallbackErrCode err)
	{

	}

	void onStunNatMap(uv::SocketAddr &addr)
	{
		std::cout << "map addr:" << addr.toStr() << std::endl;
	}
	
	void onStunSendData(const char *data, int len)
	{
		uv::SocketAddr addr("8.135.38.10", 3478);
		//uv::SocketAddr addr("192.168.0.200", 3478);
		//udpSocket->send(*global_addr, data, len);
		udpSocket->send(addr, data, len);
	}

private:
	uv::Udp *udpSocket;
};
#define SOFTWARE_VERSION  "0.0.1"

//#define TEST_WEBSOCKET_CLIENT
#define TEST_WEBSOCKET_SERVER

int main(int argc, char *argv[])
{
	std::cout << "Libuv Base APP" << std::endl;
	std::cout << "Version:" << SOFTWARE_VERSION << std::endl;
	std::string name = "test";
	uv::EventLoop* loop = uv::EventLoop::DefaultLoop();

#ifdef TEST_WEBSOCKET_SERVER
	uv::websocket::WebSocketServer wsServer(loop);
	uv::SocketAddr addr("0.0.0.0", 5000);
	wsServer.setOnConnectCallback([](int status, std::string key) {
		std::cout << "one client connect:" << key << std::endl;
	});
	wsServer.setOnMessageCallback([&](const char *data, int len, std::string key) {
		int error;
		std::cout << "recv one client data:" << key << std::endl;
		wsServer.writeData(key, data, len, error);
	});
	wsServer.setOnClosedCallback([](std::string key) {
		std::cout << "on client disconnect:" << key << std::endl;
	});
	wsServer.bindAndListen(addr);
#endif

#ifdef TEST_WEBSOCKET_CLIENT
	uv::websocket::WebSocketClient *wsClient = new uv::websocket::WebSocketClient(loop);
	uv::SocketAddr addr1("121.40.165.18", 8800);
	wsClient->setOnConnectCallback([](int status, std::string key) {
		std::cout << "connect status:" << status << std::endl;
	});
	wsClient->setOnMessageCallback([wsClient](const char *data, int len, std::string key) {
		std::cout << "data len is:" << len << std::endl;
		wsClient->close();
	});
	wsClient->setOnClosedCallback([wsClient](std::string key) {
		std::cout << "closed need delete" << std::endl;
		delete wsClient;
	});
	wsClient->connect(addr1, "/");
#endif

#ifdef TEST_STUN_SERVER
	uv::Udp udpSocket(loop);
	uv_app::STUNServer stunserver;
	uv::SocketAddr addr("0.0.0.0", 5000);
	udpSocket.bindAndRead(addr);
	udpSocket.setMessageCallback([&stunserver](uv::SocketAddr &addr, const char* data, unsigned int len) {
		stunserver.responseStun(addr);
	});
#endif

#ifdef TEST_STUN_CLIENT
	uv::Udp udpSocket(loop);
	uv_app::STUNClient stunclient(loop, name);
	uv::SocketAddr addr("0.0.0.0", 5000);
	udpSocket.bindAndRead(addr);
	udpSocket.setMessageCallback([&stunclient](uv::SocketAddr &addr, const char* data, unsigned int len) {
		global_addr = new uv::SocketAddr(addr.Addr());
		stunclient.onRecvStunData(data, len);
	});
	stunclient.init(new testClass(&udpSocket));
	stunclient.requestStun();
#endif

#ifdef TEST_DTLS_SERVER
	uv::Udp udpSocket(loop);
	uv::SocketAddr addr("192.168.0.200", 8443);
	udpSocket.bindAndRead(addr);
	Dtls::DtlsServer dtlsServer(new testClass(&udpSocket));
	dtlsServer.init("server1.cert", "server1.key", Dtls::DtlsRole::DtlsRoleServer);
	udpSocket.setMessageCallback([&dtlsServer](uv::SocketAddr& from, const char* data, unsigned size) {
		global_addr = new uv::SocketAddr(from.Addr());
		dtlsServer.onMessage(data, size);
	});
#endif

#ifdef TEST_DTLS_CLIENT
	uv::Udp udpSocket(loop);
	uv::SocketAddr addr("192.168.0.200", 5000);
	udpSocket.bindAndRead(addr);
	Dtls::DtlsClient dtlsClient(loop, new testClass(&udpSocket));
	dtlsClient.init("","",Dtls::DtlsRole::DtlsRoleClient);
	udpSocket.setMessageCallback([&dtlsClient](uv::SocketAddr& from, const char* data, unsigned size) {
		global_addr = new uv::SocketAddr(from.Addr());
		dtlsClient.onMessage(data, size);
	});
	dtlsClient.startHandShake();
#endif

#ifdef TEST_TLS_CLIENT
	uv::SocketAddr addr("192.168.0.200", 8443);
	uv::TcpClient client(loop, true);
	client.setConnectStatusCallback([](uv::TcpClient::ConnectStatus status) {
		std::cout << "connect status:" << status << std::endl;
	});
	client.setMessageCallback([&client](const char* data, ssize_t size) {
		char data1[100] = { 0 };
		memcpy(data1, data, size);
		std::cout << "recv data:" << data1 << std::endl;
		client.writeTls(data1, size, nullptr);
	});
	client.connect(addr);
#endif

#ifdef TEST_TLS_SERVER
	uv::TcpServer server(loop, true);
	server.init("server1.cert", "server1.key");
	server.setMessageCallback([](uv::TcpConnectionPtr ptr, const char* data, ssize_t size)
	{
		ptr->writeTls(data, size, nullptr);
		char data1[100] = { 0 };
		memcpy(data1, data, size);
		std::cout << "recv:" << data1 << " from name:" << ptr->Name() << std::endl;
	});
	server.setNewConnectCallback([](std::weak_ptr<uv::TcpConnection> ptr) {
		std::cout << "connect success" << ptr.lock()->Name() << std::endl;
		//ptr.lock()->writeTls("connect success\n", strlen("connect success\n"), nullptr);
	});
	server.setConnectCloseCallback([](std::weak_ptr<uv::TcpConnection> ptr) {
		std::cout << "connect close" << ptr.lock()->Name() << std::endl;
	});
	//////server.setTimeout(60); //heartbeat timeout.

	uv::SocketAddr addr("0.0.0.0", 8443, uv::SocketAddr::Ipv4);
	server.bindAndListen(addr);
#endif

	loop->run();

	return 0;
}
#endif