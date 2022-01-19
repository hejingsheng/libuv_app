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
		using OnClosedCallback = std::function<void(std::string)>;
		using OnConnectedCallback = std::function<void(int, std::string)>;
		using OnMessageCallback = std::function<void(const char* data, int len, std::string)>;

		class WebSocketServer : public uv::TcpServer
		{
		public:
			WebSocketServer(EventLoop *loop);
			virtual ~WebSocketServer();
			void setOnConnectCallback(OnConnectedCallback callback);
			void setOnMessageCallback(OnMessageCallback callback);
			void setOnClosedCallback(OnClosedCallback callback);

		private:
			void closeWs(std::string connName);
			void onMesage(TcpConnectionPtr conn, const char* data, ssize_t size);

		private:
			std::unordered_map<std::string, WebSocketProtocolBase*> connMap_;
			OnConnectedCallback connCb_;
			OnMessageCallback messCb_;
			OnClosedCallback closeCb_;
		};

		class WebSocketClient
		{
		public:
			WebSocketClient(EventLoop *loop);
			virtual ~WebSocketClient();

		public:
			void connect(SocketAddr& addr, std::string path);
			void writeData(const char *data, int len, bool text);
			void close();
			void setPingPeriod(int period);
			void setOnConnectCallback(OnConnectedCallback callback);
			void setOnMessageCallback(OnMessageCallback callback);
			void setOnClosedCallback(OnClosedCallback callback);

		private:
			void onConnectStatus(TcpClient::ConnectStatus status);
			void onMessage(const char* data, ssize_t size);
			void onTimer();
			void setPingReq();
			void onClosed();

		private:
			uv::TcpClient *client_;
			uv::Timer *pingTimer_;
			WebSocketProtocolClient *wsProtocol_;

			std::string path_;
			std::string host_;
			uint64_t pingPeriod_;

			OnConnectedCallback connCb_;
			OnMessageCallback messCb_;
			OnClosedCallback closeCb_;
		};
	};
}

#endif
