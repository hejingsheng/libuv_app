#include <functional>

#include "uv/include/UdpListener.hpp"

namespace udpListen
{
	UdpListener::UdpListener(uv::EventLoop *loop, IUdpListenCallback *callback)
	{
		udpListen_ = new uv::Udp(loop);
		udpListenCb_ = callback;
	}

	UdpListener::~UdpListener()
	{
		if (udpListen_)
		{
			udpListen_->close(nullptr);
			delete udpListen_;
			udpListen_ = nullptr;
		}
		udpListenCb_ = nullptr;
	}

	void UdpListener::init(uint16_t port)
	{
		uv::SocketAddr addr("0.0.0.0", port);
		udpListen_->bindAndRead(addr);
	}

	void UdpListener::startListen()
	{
		udpListen_->setMessageCallback(std::bind(&UdpListener::onRecvMessage, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
	}

	void UdpListener::close()
	{
		udpListen_->close(nullptr);
	}

	void UdpListener::onRecvMessage(uv::SocketAddr &addr, const char* data, unsigned int len)
	{
		if (udpListenCb_)
		{
			udpListenCb_->onUdpMsgRecv(addr, data, len);
		}
	}
}