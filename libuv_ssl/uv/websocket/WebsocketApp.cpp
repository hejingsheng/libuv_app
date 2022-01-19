#include "../include/websocket/WebsocketApp.hpp"
#include <iostream>
#include "string.h"

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

		void WebSocketServer::setOnConnectCallback(OnConnectedCallback callback)
		{
			connCb_ = callback;
		}

		void WebSocketServer::setOnMessageCallback(OnMessageCallback callback)
		{
			messCb_ = callback;
		}

		void WebSocketServer::setOnClosedCallback(OnClosedCallback callback)
		{
			closeCb_ = callback;
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
					if (connCb_)
					{
						connCb_(0, connName);
					}
				}
				else
				{
					// wait other data
					delete wsProto;
					conn->close(nullptr);
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
					WsOpCode opcode;
					int len = wsProto->decodeData(data, size, dest, finish, opcode);
					if (len == 0)
					{
						if (opcode == CLOSE_FRAME)
						{
							len = wsProto->encodeData("服务端接收发生错误EOF", strlen("服务端接收发生错误EOF"), CLOSE_FRAME, dest);
							//sendData(data.c_str(), len);
							conn->write(dest.data(), dest.length(), [this, conn](WriteInfo &winfo) {
								closeWs(conn->Name());
								conn->close(nullptr);
							});
							if (closeCb_)
							{
								closeCb_(connName);
							}
						}
						else if (opcode == PING_FRAME)
						{
							int ret = wsProto->encodeData(NULL, 0, PONG_FRAME, dest);
							conn->write(dest.data(), dest.length(), nullptr);
						}
					}
					else
					{
						std::cout << "recv data len:" << dest.length() << std::endl;
						if (messCb_)
						{
							messCb_(dest.data(), len, connName);
						}
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

		WebSocketClient::WebSocketClient(EventLoop *loop) : client_(new uv::TcpClient(loop, false)), pingPeriod_(20)
		{
			wsProtocol_ = new WebSocketProtocolClient();
			pingTimer_ = new uv::Timer(loop, pingPeriod_, 0, std::bind(&WebSocketClient::onTimer, this));
		}

		WebSocketClient::~WebSocketClient()
		{
			if (pingTimer_)
			{
				delete pingTimer_;
			}
			pingTimer_ = nullptr;
			if (wsProtocol_)
			{
				delete wsProtocol_;
			}
			wsProtocol_ = nullptr;
			if (client_)
			{
				delete client_;
			}
			client_ = nullptr;
		}

		void WebSocketClient::connect(SocketAddr& addr, std::string path)
		{
			client_->setConnectStatusCallback(std::bind(&WebSocketClient::onConnectStatus, this, std::placeholders::_1));
			client_->setMessageCallback(std::bind(&WebSocketClient::onMessage, this, std::placeholders::_1, std::placeholders::_2));

			path_ = path;
			host_ = addr.toStr();
			client_->connect(addr);
		}

		void WebSocketClient::writeData(const char *data, int len, bool text)
		{
			if (wsProtocol_->isConnected())
			{
				std::string dest = "";
				WsOpCode opcode = text ? TEXT_FRAME : BINARY_FRAME;
				wsProtocol_->encodeData(data, len, opcode, dest);
				client_->write(dest.data(), dest.length(), nullptr);
			}
		}

		void WebSocketClient::close()
		{
			//直接关闭 socket
			wsProtocol_->close();
			pingTimer_->close([this](uv::Timer *timer) {
				onClosed();
			});
		}

		void WebSocketClient::setPingPeriod(int period)
		{
			pingPeriod_ = period;
		}

		void WebSocketClient::setOnConnectCallback(OnConnectedCallback callback)
		{
			connCb_ = callback;
		}

		void WebSocketClient::setOnMessageCallback(OnMessageCallback callback)
		{
			messCb_ = callback;
		}

		void WebSocketClient::setOnClosedCallback(OnClosedCallback callback)
		{
			closeCb_ = callback;
		}

		void WebSocketClient::onConnectStatus(TcpClient::ConnectStatus status)
		{
			if (status == TcpClient::ConnectStatus::OnConnectSuccess)
			{
				std::string handshake;
				std::string extensions = "ws base libuv";
				wsProtocol_->initParam(0, path_, host_, extensions);
				wsProtocol_->doHandShake(handshake);
				client_->write(handshake.data(), handshake.length(), nullptr);
			}
			else
			{
				close();
				if (connCb_)
				{
					connCb_(-1, "");
				}
			}
		}

		void WebSocketClient::onMessage(const char* data, ssize_t size)
		{
			if (wsProtocol_->isConnected())
			{
				std::string dest = "";
				bool finish;
				WsOpCode opcode;
				int len = wsProtocol_->decodeData(data, size, dest, finish, opcode);
				if (len == 0)
				{
					if (opcode == CLOSE_FRAME)
					{
						len = wsProtocol_->encodeData("EOF", strlen("EOF"), CLOSE_FRAME, dest);
						//sendData(data.c_str(), len);
						client_->write(dest.data(), dest.length(), [this](WriteInfo &winfo) {
							//closeWs(conn->Name());
							//wsProtocol_->close();
							//client_->close(nullptr);
							close();
						});
					}
				}
				else
				{
					//std::cout << "recv data len:" << dest.length() << std::endl;
					if (messCb_)
					{
						messCb_(dest.data(), len, "");
					}
				}
			}
			else
			{
				std::string response(data, size);
				int status;
				int ret = wsProtocol_->doResponse(response);
				if (ret < 0)
				{
					close();
					status = -1;
				}
				else
				{
					pingTimer_->setTimeout(pingPeriod_ * 1000);
					pingTimer_->start();
					status = 0;
				}
				if (connCb_)
				{
					connCb_(status, "");
				}
			}
		}

		void WebSocketClient::onTimer()
		{
			setPingReq();
			pingTimer_->stop();
			pingTimer_->setTimeout(pingPeriod_ * 1000);
			pingTimer_->start();
		}

		void WebSocketClient::setPingReq()
		{
			std::string dest = "";
			int ret = wsProtocol_->encodeData(NULL, 0, PING_FRAME, dest);
			client_->write(dest.data(), dest.length());
		}

		void WebSocketClient::onClosed()
		{
			client_->close([this](uv::TcpClient* handle) {
				if (closeCb_)
				{
					closeCb_("");
				}
			});
		}
	};
}