/*
   Copyright © 2017-2020, orcaer@yeah.net  All rights reserved.

   Author: orcaer@yeah.net

   Last modified: 2019-12-31

   Description: https://github.com/wlgq2/uv-cpp
*/


#include <functional>
#include <memory>
#include <string>

#include "include/TcpServer.hpp"
#include "include/LogWriter.hpp"

using namespace std;
using namespace uv;


void uv::TcpServer::SetBufferMode(uv::GlobalConfig::BufferMode mode)
{
    uv::GlobalConfig::BufferModeStatus = mode;
}

TcpServer::TcpServer(EventLoop* loop, bool tls, bool tcpNoDelay)
    :loop_(loop),
	tls_(tls),
    tcpNoDelay_(tcpNoDelay),
    accetper_(nullptr),
    onMessageCallback_(nullptr),
    onNewConnectCallback_(nullptr),
    onConnectCloseCallback_(nullptr),
    timerWheel_(loop)
{
	if (tls_)
	{
#if OPENSSL_VERSION_NUMBER < 0x10100000L // v1.1.x
		//SSL初库始化
		SSL_library_init();
		//载入所有SSL算法
		OpenSSL_add_ssl_algorithms();
		//载入所有错误信息
		SSL_load_error_strings();
#else
#endif
	}
}

TcpServer:: ~TcpServer()
{

}

void TcpServer::setTimeout(unsigned int seconds)
{
    timerWheel_.setTimeout(seconds);
}

void uv::TcpServer::onAccept(EventLoop * loop, UVTcpPtr client)
{
    string key;
    SocketAddr::AddrToStr(client.get(), key, ipv_);

    uv::LogWriter::Instance()->debug("new connect  " + key);
    shared_ptr<TcpConnection> connection(new TcpConnection(loop, key, client, tls_, true));
    if (connection)
    {
        connection->setMessageCallback(std::bind(&TcpServer::onMessage, this, placeholders::_1, placeholders::_2, placeholders::_3));
        connection->setConnectCloseCallback(std::bind(&TcpServer::closeConnection, this, placeholders::_1));
        addConnnection(key, connection);
        if (timerWheel_.getTimeout() > 0)
        {
            auto wrapper = std::make_shared<ConnectionWrapper>(connection);
            connection->setWrapper(wrapper);
            timerWheel_.insert(wrapper);
        }
		if (tls_)
		{
			connection->init(certFile_, keyFile_, TLSRole::TLSServer);
		}
		else
		{
			if (onNewConnectCallback_)
				onNewConnectCallback_(connection);
		}
    }
    else
    {
        uv::LogWriter::Instance()->error("create connection fail. :" + key);
    }
}

void TcpServer::init(std::string cert, std::string key)
{
	if (tls_)
	{
		certFile_ = std::move(cert);
		keyFile_ = std::move(key);
	}
}

int TcpServer::bindAndListen(SocketAddr& addr)
{
    ipv_ = addr.Ipv();
    accetper_ = std::make_shared<TcpAccepter>(loop_, tcpNoDelay_);
    auto rst = accetper_->bind(addr);
    if (0 != rst)
    {
        return rst;
    }
    accetper_->setNewConnectinonCallback(std::bind(&TcpServer::onAccept, this, std::placeholders::_1, std::placeholders::_2));
    timerWheel_.start();
    return accetper_->listen();
}

void TcpServer::close(DefaultCallback callback)
{
    if (accetper_)
        accetper_->close([this, callback]()
    {
        for (auto& connection : connnections_)
        {
            connection.second->onSocketClose();
        }
        callback();
    });
}

void TcpServer::addConnnection(std::string& name,TcpConnectionPtr connection)
{
    connnections_.insert(pair<string,shared_ptr<TcpConnection>>(std::move(name),connection));
}

void TcpServer::removeConnnection(string& name)
{
    connnections_.erase(name);
}

shared_ptr<TcpConnection> TcpServer::getConnnection(const string& name)
{
    auto rst = connnections_.find(name);
    if(rst == connnections_.end())
    {
        return nullptr;
    }
    return rst->second;
}

void TcpServer::closeConnection(const string& name)
{
    auto connection = getConnnection(name);
    if (nullptr != connection)
    {
        connection->close([this](std::string& name)
        {
            auto connection = getConnnection(name);
            if (nullptr != connection)
            {
                if (onConnectCloseCallback_)
                {
                    onConnectCloseCallback_(connection);
                }
                removeConnnection(name);
            }

        });
    }
}


void TcpServer::onMessage(TcpConnectionPtr connection,const char* buf,ssize_t size)
{
	if (tls_)
	{
		if (buf == nullptr && size == 0)
		{
			if (onNewConnectCallback_)
				onNewConnectCallback_(connection);
		}
		else
		{
			if (onMessageCallback_)
				onMessageCallback_(connection, buf, size);
		}
	}
	else
	{
		if (onMessageCallback_)
			onMessageCallback_(connection, buf, size);
	}
    if (timerWheel_.getTimeout() > 0)
    {
        timerWheel_.insert(connection->getWrapper());
    }
}


void TcpServer::setMessageCallback(OnMessageCallback callback)
{
    onMessageCallback_ = callback;
}


void TcpServer::write(shared_ptr<TcpConnection> connection,const char* buf,unsigned int size, AfterWriteCallback callback)
{
    if(nullptr != connection)
    {
        connection->write(buf,size, callback);
    }
    else if (callback)
    {
        WriteInfo info = { WriteInfo::Disconnected,const_cast<char*>(buf),size };
        callback(info);
    }
}

void TcpServer::write(string& name,const char* buf,unsigned int size,AfterWriteCallback callback)
{
    auto connection = getConnnection(name);
    write(connection, buf, size, callback);
}

void TcpServer::writeInLoop(shared_ptr<TcpConnection> connection,const char* buf,unsigned int size,AfterWriteCallback callback)
{
    if(nullptr != connection)
    {
        connection->writeInLoop(buf,size,callback);
    }
    else if (callback)
    {
        uv::LogWriter::Instance()->warn("try write a disconnect connection.");
        WriteInfo info = { WriteInfo::Disconnected,const_cast<char*>(buf),size };
        callback(info);
    }
}

void TcpServer::writeInLoop(string& name,const char* buf,unsigned int size,AfterWriteCallback callback)
{
    auto connection = getConnnection(name);
    writeInLoop(connection, buf, size, callback);
}

void TcpServer::setNewConnectCallback(OnConnectionStatusCallback callback)
{
    onNewConnectCallback_ = callback;
}

void  TcpServer::setConnectCloseCallback(OnConnectionStatusCallback callback)
{
    onConnectCloseCallback_ = callback;
}
