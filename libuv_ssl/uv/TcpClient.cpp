/*
   Copyright © 2017-2020, orcaer@yeah.net  All rights reserved.

   Author: orcaer@yeah.net

   Last modified: 2019-12-31

   Description: https://github.com/wlgq2/uv-cpp
*/

#include <string>

#include "include/TcpClient.hpp"
#include "include/LogWriter.hpp"
#include "include/Packet.hpp"

using namespace uv;
using namespace std;


TcpClient::TcpClient(EventLoop* loop, bool tls, bool tcpNoDelay)
	:loop_(loop),
	connect_(new uv_connect_t()),
	ipv(SocketAddr::Ipv4),
	tcpNoDelay_(tcpNoDelay),
	tls_(tls),
    connectCallback_(nullptr),
    onMessageCallback_(nullptr),
    connection_(nullptr)
{
    connect_->data = static_cast<void*>(this);
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

TcpClient::~TcpClient()
{
    delete connect_;
}

bool uv::TcpClient::isTcpNoDelay()
{
    return tcpNoDelay_;
}

void uv::TcpClient::setTcpNoDelay(bool isNoDelay)
{
    tcpNoDelay_ = isNoDelay;
}


void TcpClient::connect(SocketAddr& addr)
{
    update();
    ipv = addr.Ipv();    
    ::uv_tcp_connect(connect_, socket_.get(), addr.Addr(), [](uv_connect_t* req, int status)
    {
        auto handle = static_cast<TcpClient*>((req->data));
        if (0 != status)
        {
            uv::LogWriter::Instance()->error( "connect fail.");
            handle->onConnect(false);
            return;
        }

        handle->onConnect(true);
    });
}

void TcpClient::onConnect(bool successed)
{
	int ret;
    if(successed)
    {
        string name;
        SocketAddr::AddrToStr(socket_.get(),name,ipv);

        connection_ = make_shared<TcpConnection>(loop_, name, socket_, tls_);
        connection_->setMessageCallback(std::bind(&TcpClient::onMessage,this,std::placeholders::_1,std::placeholders::_2,std::placeholders::_3));
        connection_->setConnectCloseCallback(std::bind(&TcpClient::onConnectClose,this,std::placeholders::_1));
		if (tls_)
		{
			ret = connection_->init("", "", TLSRole::TLSClient);
			if (ret == 0)
			{
				runConnectCallback(TcpClient::OnConnectSuccess);
			}
			else if (ret < 0)
			{
				connection_->close(nullptr);
				runConnectCallback(TcpClient::OnConnnectFail);
			}
		}
		else
		{
			runConnectCallback(TcpClient::OnConnectSuccess);
		}
    }
    else
    {
        if (::uv_is_active((uv_handle_t*)socket_.get()))
        {
            ::uv_read_stop((uv_stream_t*)socket_.get());
        }
        if (::uv_is_closing((uv_handle_t*)socket_.get()) == 0)
        {
            socket_->data = static_cast<void*>(this);
            ::uv_close((uv_handle_t*)socket_.get(),
                [](uv_handle_t* handle)
            {
                auto client = static_cast<TcpClient*>(handle->data);
                client->afterConnectFail();
            });
        }
    }
}

void TcpClient::onConnectClose(string& name)
{
    if (connection_)
    {
        connection_->close(std::bind(&TcpClient::onClose,this,std::placeholders::_1));
    }

}
void TcpClient::onMessage(shared_ptr<TcpConnection> connection,const char* buf,ssize_t size)
{
	if (tls_)
	{
		if (buf == nullptr && size == 0)
		{
			runConnectCallback(TcpClient::OnConnectSuccess);
		}
		else
		{
			if (onMessageCallback_)
				onMessageCallback_(buf, size);
		}
	}
	else
	{
		if (onMessageCallback_)
			onMessageCallback_(buf, size);
	}
}

void uv::TcpClient::close(std::function<void(uv::TcpClient*)> callback)
{
	if (tls_)
	{
		
	}
    if (connection_)
    {
        connection_->close([this, callback](std::string&)
        {
            //onClose(name);
            if (callback)
                callback(this);
        });

    }
    else if(callback)
    {
        callback(this);
    }
}

void uv::TcpClient::afterConnectFail()
{
    runConnectCallback(TcpClient::OnConnnectFail);
}

void uv::TcpClient::write(const char* buf, unsigned int size, AfterWriteCallback callback)
{
    if (connection_)
    {
        connection_->write(buf, size, callback);
    }
    else if(callback)
    {
        uv::LogWriter::Instance()->warn("try write a disconnect connection.");
        WriteInfo info = { WriteInfo::Disconnected,const_cast<char*>(buf),size };
        callback(info);
    }

}

void uv::TcpClient::writeInLoop(const char * buf, unsigned int size, AfterWriteCallback callback)
{
    if (connection_)
    {
        connection_->writeInLoop(buf, size, callback);
    }
    else if(callback)
    {
        uv::LogWriter::Instance()->warn("try write a disconnect connection.");
        WriteInfo info = { WriteInfo::Disconnected,const_cast<char*>(buf),size };
        callback(info);
    }
}

void uv::TcpClient::writeTls(const char *buf, unsigned int size, AfterWriteCallback callback)
{
	if (!tls_)
	{
		uv::LogWriter::Instance()->warn("status error");
		return;
	}
	connection_->writeTls(buf, size, nullptr);
}

void uv::TcpClient::setConnectStatusCallback(ConnectStatusCallback callback)
{
    connectCallback_ = callback;
}

void uv::TcpClient::setMessageCallback(NewMessageCallback callback)
{
    onMessageCallback_ = callback;
}

EventLoop* uv::TcpClient::Loop()
{
    return loop_;
}

PacketBufferPtr uv::TcpClient::getCurrentBuf()
{
    if (connection_)
        return connection_->getPacketBuffer();
    return nullptr;
}


void TcpClient::update()
{
    socket_ = make_shared<uv_tcp_t>();
    ::uv_tcp_init(loop_->handle(), socket_.get());
    if (tcpNoDelay_)
        ::uv_tcp_nodelay(socket_.get(), 1 );
}

void uv::TcpClient::runConnectCallback(TcpClient::ConnectStatus satus)
{
    if (connectCallback_)
        connectCallback_(satus);
}

void uv::TcpClient::onClose(std::string& name)
{
    //connection_ = nullptr;
    uv::LogWriter::Instance()->info("Close tcp client connection complete.");
    runConnectCallback(TcpClient::OnConnnectClose);
}
