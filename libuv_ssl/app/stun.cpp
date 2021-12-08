#include <sstream>
#include "string.h"
#include "stun.h"

#define LITTLEENDIAN_ARCH 1
namespace uv_app
{
	static int write_int8(void* dest, const void* src) {
		*(uint8_t*)dest = *(uint8_t*)src;
		return sizeof(uint8_t);
	}

#if BIGENDIAN_ARCH
	static int write_int16(void* _dest, void* _src) {
		register uint8_t* dest = _dest;
		register uint8_t* src = _src;
		dest[0] = src[0];
		dest[1] = src[1];
		return sizeof(uint16_t);
	}
	static int write_int32(void* _dest, void* _src) {
		register uint8_t* dest = _dest;
		register uint8_t* src = _src;
		dest[0] = src[0];
		dest[1] = src[1];
		dest[2] = src[2];
		dest[3] = src[3];
		return sizeof(uint32_t);
	}
#endif
#if LITTLEENDIAN_ARCH
	static int write_int16(void* _dest, const void* _src) {
		register uint8_t* dest = (uint8_t*)_dest; 
		register uint8_t* src = (uint8_t*)_src;
		dest[0] = src[1];
		dest[1] = src[0];
		return sizeof(uint16_t);
	}
	static int write_int32(void* _dest, const void* _src) {
		register uint8_t* dest = (uint8_t*)_dest; 
		register uint8_t* src = (uint8_t*)_src;
		dest[0] = src[3];
		dest[1] = src[2];
		dest[2] = src[1];
		dest[3] = src[0];
		return sizeof(uint32_t);
	}
#endif


	static std::string general_random_str(int len)
	{
		static std::string random_table = "01234567890123456789012345678901234567890123456789abcdefghijklmnopqrstuvwxyz";

		std::string ret;
		ret.reserve(len);
		for (int i = 0; i < len; ++i) {
			ret.append(1, random_table[rand() % random_table.size()]);
		}
		return ret;
	}
	static unsigned char SWAP_UINT8(unsigned char* p)
	{
		if (!p)
			return 0;
		return (unsigned char)(*p);
	}
	static unsigned short SWAP_UINT16(unsigned char* p)
	{
		unsigned short a = 0;
		unsigned char* pa = (unsigned char*)&a;
		pa[1] = SWAP_UINT8(p++);
		pa[0] = SWAP_UINT8(p);
		return a;
	}
	static unsigned int SWAP_UINT32(unsigned char* p)
	{
		unsigned int a = 0;
		unsigned char* pa = (unsigned char*)&a;
		pa[3] = SWAP_UINT8(p++);
		pa[2] = SWAP_UINT8(p++);
		pa[1] = SWAP_UINT8(p++);
		pa[0] = SWAP_UINT8(p);
		return a;
	}


	StunMsgPacket::StunMsgPacket()
	{
		stunMsgType = 0;
		stunMsgLenght = 0;
		stunMagicCookie = 0;
	}

	StunMsgPacket::~StunMsgPacket()
	{

	}

	void StunMsgPacket::encode(char *data, int size)
	{
		char tmp[1024] = {0};
		char *p = data;
		char *q = tmp;
		uint16_t tmplen;

		std::map<uint16_t, std::string>::iterator it;
		for (it = stunAttribute.begin(); it != stunAttribute.end(); it++)
		{
			uint16_t type = it->first;
			uint16_t len = it->second.length();
			uint16_t padding = 0;
			switch (type)
			{
			case Username:
			case Software:
				q += write_int16(q, (void*)&type);
				q += write_int16(q, (void*)&len);
				memcpy(q, it->second.c_str(), len);
				q += len;
				if (len % 4 != 0)
				{
					padding = 4 - (len % 4);
					memset(q, 0x00, padding);
					q += padding;
				}
				break;
			case MappedAddress:
				{
					size_t pos = it->second.find(":");
					uint16_t port;
					struct in_addr addr;
					std::string ipaddr;
					if (pos != std::string::npos)
					{
						q += write_int16(q, (void*)&type);
						len = 8;
						q += write_int16(q, (void*)&len);
						*q = 0x00;
						q += sizeof(uint8_t);
						*q = 0x01;
						q += sizeof(uint8_t);
						ipaddr = it->second.substr(0, pos);
						//inet_aton(ipaddr.c_str(), &addr);
						addr.s_addr = inet_addr(ipaddr.c_str());
						addr.s_addr = htonl(addr.s_addr);
						port = atoi(it->second.substr(pos + 1).c_str());
						q += write_int16(q, (void*)&port);
						q += write_int32(q, (void*)&(addr.s_addr));
					}
				}
				break;
			case XorMappedAddress:
				{
					size_t pos = it->second.find(":");
					uint16_t port;
					struct in_addr addr;
					std::string ipaddr;
					if (pos != std::string::npos)
					{
						q += write_int16(q, (void*)&type);
						len = 8;
						q += write_int16(q, (void*)&len);
						*q = 0x00;
						q += sizeof(uint8_t);
						*q = 0x01;
						q += sizeof(uint8_t);
						ipaddr = it->second.substr(0, pos);
						addr.s_addr = inet_addr(ipaddr.c_str());
						addr.s_addr = htonl(addr.s_addr);
						port = atoi(it->second.substr(pos + 1).c_str());
						port = port ^ ((stunMagicCookie & 0xffff0000) >> 16);
						q += write_int16(q, (void*)&port);
						uint32_t tmp = addr.s_addr ^ stunMagicCookie;
						q += write_int32(q, (void*)&tmp);
					}
				}
				break;
			default:
				break;
			}
		}
		p += write_int16(p, (void*)&stunMsgType);
		stunMsgLenght = q - tmp;
		p += write_int16(p, (void*)&stunMsgLenght);
		p += write_int32(p, (void*)&stunMagicCookie);
		memcpy(p, (void*)stunTranId, 12);
		p += 12;
		memcpy(p, tmp, stunMsgLenght);
	}

	void StunMsgPacket::decode(const char *buf, int len)
	{
		if (len < 20)
		{
			//error len
			return;
		}
		std::ostringstream ostr;
		const char *p = buf;
		int index = 0;
		
		stunMsgType = (p[0] << 8 | p[1]);
		stunMsgLenght = (p[2] << 8 | p[3]);
		stunMagicCookie |= ((p[4] & 0x000000ff) << 24);
		stunMagicCookie |= ((p[5] & 0x000000ff) << 16);
		stunMagicCookie |= ((p[6] & 0x000000ff) << 8);
		stunMagicCookie |= (p[7] & 0x000000ff);
		memcpy(stunTranId, p + 8, 12);
		index = 20;
		if (stunMsgType == StunBindRespones)
		{
			while (index < len)
			{
				uint16_t type = p[index] << 8 | p[index + 1];
				index += 2;
				uint16_t len = p[index] << 8 | p[index + 1];
				index += 2;
				std::string val = std::string(p + index, len);
				if (len % 4 != 0)
				{
					len = ((len / 4) + 1) * 4;
				}
				index += len;
				switch (type)
				{
				case Username:
				{
					stunAttribute.insert(std::make_pair(Username, val));
				}
				break;
				case XorMappedAddress:
				{
					char reserved = val.at(0);
					char protocolFamily = val.at(1);
					uint16_t port = ((val.at(2) & 0x00ff) << 8 | (val.at(3) & 0x00ff)) ^ ((stunMagicCookie & 0xffff0000) >> 16);
					uint32_t ipaddr = ((val.at(4) & 0x000000ff) << 24 | (val.at(5) & 0x000000ff) << 16 | (val.at(6) & 0x000000ff) << 8 | (val.at(7) & 0x000000ff)) ^ stunMagicCookie;
					ipaddr = ntohl(ipaddr);
					struct in_addr addr;
					addr.s_addr = ipaddr;
					char *tmp = inet_ntoa(addr);
					ostr << tmp << ":" << port;
					stunAttribute.insert(std::make_pair(XorMappedAddress, ostr.str()));
					ostr.str("");
				}
				break;
				case MappedAddress:
				{
					char reserved = val.at(0);
					char protocolFamily = val.at(1);
					uint16_t port = ((val.at(2) & 0x00ff) << 8 | (val.at(3) & 0x00ff));
					uint32_t ipaddr = ((val.at(4) & 0x000000ff) << 24 | (val.at(5) & 0x000000ff) << 16 | (val.at(6) & 0x000000ff) << 8 | (val.at(7) & 0x000000ff));
					ipaddr = ntohl(ipaddr);
					struct in_addr addr;
					addr.s_addr = ipaddr;
					char *tmp = inet_ntoa(addr);
					ostr << tmp << ":" << port;
					stunAttribute.insert(std::make_pair(MappedAddress, ostr.str()));
					ostr.str("");
				}
				break;
				default:
					//not deal 
					break;
				}
			}
		}
		else if (stunMsgType == StunBindError)
		{
			
		}
		else
		{

		}
	}

	STUNBase::STUNBase()
	{

	}

	STUNBase::~STUNBase()
	{
		stunCb_ = nullptr;
	}

	void STUNBase::init(IStunCallback *callback)
	{
		stunCb_ = callback;
	}

	void STUNBase::onRecvStunData(const char *data, int len)
	{
		packet.decode(data, len);
	}

	STUNServer::STUNServer()
	{

	}

	STUNServer::~STUNServer()
	{

	}

	void STUNServer::responseStun(uv::SocketAddr &addr)
	{
		char msg[1024] = { 0 };
		int len;

		buildBindResponse(msg, sizeof(msg), len, addr);
		if (stunCb_)
		{
			stunCb_->onStunSendData(msg, len);
		}
	}

	void STUNServer::requestStun()
	{
		return;
	}

	void STUNServer::buildBindResponse(char *data, int size, int &len, uv::SocketAddr &addr)
	{
		StunMsgPacket stunMsg;
		stunMsg.stunMsgType = StunBindRespones;
		stunMsg.stunMagicCookie = 0x2112a442;
		for (int i = 0; i < 12; i++)
		{
			stunMsg.stunTranId[i] = packet.stunTranId[i];
		}
		if (packet.stunAttribute.find(Username) != packet.stunAttribute.end())
		{
			stunMsg.stunAttribute.insert(std::make_pair(Username, packet.stunAttribute.find(Username)->second));
		}
		stunMsg.stunAttribute.insert(std::make_pair(XorMappedAddress, addr.toStr()));
		stunMsg.stunAttribute.insert(std::make_pair(MappedAddress, addr.toStr()));
		stunMsg.stunAttribute.insert(std::make_pair(Software, "Libuv App StunServer(HeJingsheng)"));
		stunMsg.encode(data, size);
		len = stunMsg.stunMsgLenght + 20;
	}

	STUNClient::STUNClient(uv::EventLoop *loop, std::string username) : username_(username)
	{
		retryTimer_ = new uv::Timer(loop, 1000, 0, std::bind(&STUNClient::startRetransmitTimer, this));
		maxRetryNum = 5;
		stunCb_ = nullptr;
		initRtt = 500;
	}

	STUNClient::~STUNClient()
	{
		if (retryTimer_)
		{
			delete retryTimer_;
			retryTimer_ = nullptr;
		}
		stunCb_ = nullptr;
	}

	void STUNClient::startRetransmitTimer()
	{
		if (stunCb_)
		{
			maxRetryNum--;
			if (maxRetryNum <= 0)
			{
				stunCb_->onStunFail(StunErrorTimeOut);
			}
			else
			{
				initRtt = initRtt * 2;
				requestStun();
			}
		}
	}

	void STUNClient::buildBindRequest(char *data, int size, int &len)
	{
		StunMsgPacket stunMsg;
		stunMsg.stunMsgType = StunBindRequest;
		stunMsg.stunMagicCookie = 0x2112a442;
		std::string transportId = general_random_str(12);
		transportIdVec_.push_back(transportId);
		for (int i = 0; i < 12; i++)
		{
			stunMsg.stunTranId[i] = transportId.at(i);
		}
		if (!username_.empty())
		{
			stunMsg.stunAttribute.insert(std::make_pair(Username, username_));
			//stunMsg.stunAttribute.insert(std::make_pair(XorMappedAddress, "192.168.0.200:10000"));
			//stunMsg.stunAttribute.insert(std::make_pair(MappedAddress, "8.135.38.10:5000"));
		}
		stunMsg.stunAttribute.insert(std::make_pair(Software, "Libuv App Stun(HeJingsheng)"));
		stunMsg.encode(data, size);
		len = stunMsg.stunMsgLenght + 20;
	}

	void STUNClient::requestStun()
	{
		char msg[1024] = { 0 };
		int len;

		buildBindRequest(msg, sizeof(msg), len);
		if (stunCb_)
		{
			stunCb_->onStunSendData(msg, len);
		}
		retryTimer_->stop();
		retryTimer_->setTimeout(initRtt);
		retryTimer_->start();
	}

	void STUNClient::responseStun(uv::SocketAddr &addr)
	{
		return;
	}

	void STUNClient::onRecvStunData(const char *data, int len)
	{
		STUNBase::onRecvStunData(data, len);
		if (packet.stunAttribute.find(XorMappedAddress) == packet.stunAttribute.end() && packet.stunAttribute.find(MappedAddress) == packet.stunAttribute.end())
		{
			stunCb_->onStunFail(StunErrorServer);
		}
		else
		{	
			std::string value;
			if (packet.stunAttribute.find(XorMappedAddress) != packet.stunAttribute.end()) 
			{
				value = packet.stunAttribute.find(XorMappedAddress)->second;
			}
			else
			{
				value = packet.stunAttribute.find(XorMappedAddress)->second;
			}
			size_t pos = value.find(":");
			uint16_t port;
			std::string ipaddr;

			ipaddr = value.substr(0, pos);
			const char *t = value.substr(pos + 1).c_str();
			port = atoi(value.substr(pos + 1).c_str());
			uv::SocketAddr sockaddr(ipaddr, port);
			stunCb_->onStunNatMap(sockaddr);
			retryTimer_->stop();
		}
	}


}