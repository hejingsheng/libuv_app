#ifndef _WEBSOCKET_SERVER_H_
#define _WEBSOCKET_SERVER_H_

#include "../TcpServer.hpp"
#include "../TcpClient.hpp"
#include "../app/wsProtocol.h"
#include <unordered_map>

namespace uv
{
	namespace websocket
	{
		class WebSocketServer : public uv::TcpServer
		{
		public:
			WebSocketServer(EventLoop *loop);
			virtual ~WebSocketServer();

		private:
			void closeWs(std::string connName);
			void onMesage(TcpConnectionPtr conn, const char* data, ssize_t size);

		private:
			std::unordered_map<std::string, WebSocketProtocolBase*> connMap_;
		};

		class WebSocketClient
		{
		public:
			WebSocketClient(EventLoop *loop);
			virtual ~WebSocketClient();

		public:
			void connect(SocketAddr& addr);

		private:
			void onConnectStatus(TcpClient::ConnectStatus status);
			void onMessage(const char* data, ssize_t size);

		private:
			uv::TcpClient *client_;
			WebSocketProtocolClient *wsProtocol_;
		};
	};
}

#endif
