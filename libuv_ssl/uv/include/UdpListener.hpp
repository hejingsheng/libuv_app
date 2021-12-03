#ifndef _UDP_LISTEN_H_
#define _UDP_LISTEN_H_

#include <string>

#include "uv/include/uv11.hpp"
#include "uv/include/Udp.hpp"

namespace udpListen
{
	class IUdpListenCallback
	{
	public:
		virtual void onUdpMsgRecv(uv::SocketAddr &addr, const char *data, unsigned int len) = 0;

		virtual ~IUdpListenCallback() = default;
	};

	class UdpListener
	{
	public:
		UdpListener(uv::EventLoop *loop, IUdpListenCallback *callback);
		virtual ~UdpListener();

	public:
		void init(uint16_t port);
		void startListen();
		void close();

	private:
		void onRecvMessage(uv::SocketAddr &addr, const char* data, unsigned int len);

	private:
		uv::Udp *udpListen_;

		IUdpListenCallback *udpListenCb_;
	};
}

#endif