/*
   Copyright © 2017-2019, orcaer@yeah.net  All rights reserved.

   Author: orcaer@yeah.net

   Last modified: 2019-12-31

   Description: https://github.com/wlgq2/uv-cpp
*/

#ifndef UV_TCP_SERVER_HPP
#define UV_TCP_SERVER_HPP

#include <functional>
#include <memory>
#include <set>
#include <map>

#include "TcpAccepter.hpp"
#include "TcpConnection.hpp"
#include "TimerWheel.hpp"

namespace uv
{

using OnConnectionStatusCallback =  std::function<void (std::weak_ptr<TcpConnection> )> ;

//no thread safe.
class TcpServer
{
public:
    static void SetBufferMode(uv::GlobalConfig::BufferMode mode);
public:
    TcpServer(EventLoop* loop, bool tls, bool tcpNoDelay = true);
    virtual ~TcpServer();
	void init(std::string cert, std::string key);
    int bindAndListen(SocketAddr& addr);
    void close(DefaultCallback callback);
    
    TcpConnectionPtr getConnnection(const std::string& name);
    void closeConnection(const std::string& name);

    void setNewConnectCallback(OnConnectionStatusCallback callback);
    void setConnectCloseCallback(OnConnectionStatusCallback callback);

    void setMessageCallback(OnMessageCallback callback);

    void write(TcpConnectionPtr connection,const char* buf,unsigned int size, AfterWriteCallback callback = nullptr);
    void write(std::string& name,const char* buf,unsigned int size, AfterWriteCallback callback =nullptr);
    void writeInLoop(TcpConnectionPtr connection,const char* buf,unsigned int size,AfterWriteCallback callback);
    void writeInLoop(std::string& name,const char* buf,unsigned int size,AfterWriteCallback callback);

    void setTimeout(unsigned int);
private:
    void onAccept(EventLoop* loop, UVTcpPtr client);

    void addConnnection(std::string& name, TcpConnectionPtr connection);
    void removeConnnection(std::string& name);
    void onMessage(TcpConnectionPtr connection, const char* buf, ssize_t size);
protected:
    EventLoop* loop_;
private:
    bool tcpNoDelay_;
	bool tls_;
	std::string certFile_;
	std::string keyFile_;
    SocketAddr::IPV ipv_;
    std::shared_ptr <TcpAccepter> accetper_;
    std::map<std::string ,TcpConnectionPtr>  connnections_;


    OnMessageCallback onMessageCallback_;
    OnConnectionStatusCallback onNewConnectCallback_;
	OnConnectionStatusCallback onConnectCloseCallback_;
    TimerWheel<ConnectionWrapper> timerWheel_;
};


}
#endif
