#include "../include/websocket/WebsocketApp.hpp"
#include <iostream>

namespace uv
{
	namespace websocket
	{
		WebSocketServer::WebSocketServer(EventLoop *loop) : uv::TcpServer(loop, false)
		{
			setMessageCallback(std::bind(&WebSocketServer::onMesage, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
			//setConnectCloseCallback(std::bind(&WebSocketServer::onClose, this, std::placeholders::_1));
		}

		WebSocketServer::~WebSocketServer()
		{
			std::unordered_map<std::string, WebSocketProtocolBase*>::iterator it = connMap_.begin();
			for (; it != connMap_.end(); it++)
			{
				it->second->close();
				delete it->second;
			}
		}

		void WebSocketServer::onMesage(TcpConnectionPtr conn, const char* data, ssize_t size)
		{
			std::string connName = conn->Name();
			WebSocketProtocolBase *wsProto;
			int ret;
			if (connMap_.find(connName) == connMap_.end())
			{
				// 第一次连接 或者 没有连接成功
				wsProto = new WebSocketProtocolServer();
				std::string handshake(data, size);
				ret = wsProto->doHandShake(handshake);
				if (ret == 0)
				{
					std::string response;
					wsProto->doResponse(response);
					conn->write(response.data(), response.length(), nullptr);
					connMap_.insert(std::make_pair(connName, wsProto));
				}
				else
				{
					// wait other data
				}
			}
			else
			{
				// 已经连接成功
				wsProto = connMap_[connName];
				if (wsProto != nullptr && wsProto->isConnected())
				{
					std::string dest = "";
					bool finish;
					int len = wsProto->decodeData(data, size, dest, finish);
					if (len == 0)
					{
						len = wsProto->encodeData("服务端接收发生错误EOF", strlen("服务端接收发生错误EOF"), dest);
						//sendData(data.c_str(), len);
						conn->write(dest.data(), dest.length(), [this, conn](WriteInfo &winfo) {
							closeWs(conn->Name());
							conn->close(nullptr);
						});
					}
					else
					{
						std::cout << "recv data len:" << dest.length() << std::endl;
					}
				}
				else
				{
					//
				}
			}
		}

		void WebSocketServer::closeWs(std::string connName)
		{
			if (connMap_.find(connName) != connMap_.end())
			{
				WebSocketProtocolBase *wsProto = connMap_[connName];
				if (wsProto != nullptr)
				{
					wsProto->close();
					delete wsProto;
				}
				connMap_.erase(connName);
			}
		}

		WebSocketClient::WebSocketClient(EventLoop *loop) : client_(new uv::TcpClient(loop, false))
		{
			wsProtocol_ = new WebSocketProtocolClient();
		}

		WebSocketClient::~WebSocketClient()
		{
			if (wsProtocol_)
			{
				delete wsProtocol_;
			}
			wsProtocol_ = nullptr;
		}

		void WebSocketClient::connect(SocketAddr& addr)
		{
			client_->setConnectStatusCallback(std::bind(&WebSocketClient::onConnectStatus, this, std::placeholders::_1));
			client_->setMessageCallback(std::bind(&WebSocketClient::onMessage, this, std::placeholders::_1, std::placeholders::_2));
			client_->connect(addr);
		}

		void WebSocketClient::onConnectStatus(TcpClient::ConnectStatus status)
		{
			if (status == TcpClient::ConnectStatus::OnConnectSuccess)
			{
				std::string handshake;
				std::string path = "/";
				std::string host = "121.40.165.18:8800"; 
				std::string extensions = "ws base libuv";
				wsProtocol_->initParam(0, path, host, extensions);
				wsProtocol_->doHandShake(handshake);
				client_->write(handshake.data(), handshake.length(), nullptr);
			}
			else
			{

			}
		}

		void WebSocketClient::onMessage(const char* data, ssize_t size)
		{
			if (wsProtocol_->isConnected())
			{
				std::string dest = "";
				bool finish;
				int len = wsProtocol_->decodeData(data, size, dest, finish);
				if (len == 0)
				{
					len = wsProtocol_->encodeData("EOF", strlen("EOF"), dest);
					//sendData(data.c_str(), len);
					client_->write(dest.data(), dest.length(), [this](WriteInfo &winfo) {
						//closeWs(conn->Name());
						wsProtocol_->close();
						client_->close(nullptr);
					});
				}
				else
				{
					std::cout << "recv data len:" << dest.length() << std::endl;
				}
			}
			else
			{
				std::string response(data, size);
				wsProtocol_->doResponse(response);
			}
		}
	};
}