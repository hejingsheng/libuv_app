#include <string>
#include <sstream>
#include <ctime>
#include <iostream>
#include <functional>
#include <algorithm>
#include "wsProtocol.h"
#include "string.h"
#include "sha1.h"

static std::string generateRandom(int len) {
	const char charset[] = "0123456789" "abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "+-*/=";
	const size_t size = sizeof(charset) - 1;

	auto randomChar = [&]() {
		return charset[rand() % size];
	};

	auto resultSize = len;
	std::string result(resultSize, 0);
	std::generate_n(result.begin(), resultSize, randomChar);

	return result;
}

int WsHeader::encode(std::string &header)
{
	uint8_t byte;
	byte = eof ? (0x01 << 7) : 0x00;
	byte |= (opcode & 0x0f);
	header.append(1, byte);
	byte = mask ? (0x01 << 7) : 0x00;
	if (len < 126)
	{
		byte |= (len & 0x7f);
		header.append(1, byte);
	}
	else if (len < MAX_UINT16)
	{
		byte |= 126;
		header.append(1, byte);
		byte = (uint8_t)((len & 0xff00) >> 8);
		header.append(1, byte);
		byte = (uint8_t)(len & 0x00ff);
		header.append(1, byte);
	}
	else
	{
		byte |= 127;
		header.append(1, byte);
		byte = (uint8_t)((len & 0xff00000000000000) >> 56);
		header.append(1, byte);
		byte = (uint8_t)((len & 0x00ff000000000000) >> 48);
		header.append(1, byte);
		byte = (uint8_t)((len & 0x0000ff0000000000) >> 40);
		header.append(1, byte);
		byte = (uint8_t)((len & 0x000000ff00000000) >> 32);
		header.append(1, byte);
		byte = (uint8_t)((len & 0x00000000ff000000) >> 24);
		header.append(1, byte);
		byte = (uint8_t)((len & 0x0000000000ff0000) >> 16);
		header.append(1, byte);
		byte = (uint8_t)((len & 0x000000000000ff00) >> 8);
		header.append(1, byte);
		byte = (uint8_t)(len & 0x00000000000000ff);
		header.append(1, byte);
	}
	if (mask)
	{
		byte = mask_key[0];
		header.append(1, byte);
		byte = mask_key[1];
		header.append(1, byte);
		byte = mask_key[2];
		header.append(1, byte);
		byte = mask_key[3];
		header.append(1, byte);
	}
	return header.size();
}

int WsHeader::decode(const char *header, int length)
{
	uint8_t byte;
	int offset = 0;

	byte = header[offset];
	eof = (byte >> 7) > 0;
	opcode = byte & 0x0F;
	offset++;
	byte = header[offset];
	mask = (byte >> 7) > 0;
	len = static_cast<uint64_t>(byte & 0x7f);
	offset++;
	if (len == 126)
	{
		len = 0;
		len |= (header[offset] & 0x00000000000000ff) << 8;
		len |= header[offset + 1] & 0x00000000000000ff;
		offset += 2;
	}
	else if (len == 127)
	{
		len = 0;
		len |= (header[offset] & 0x00000000000000ff) << 56;
		len |= (header[offset + 1] & 0x00000000000000ff) << 48;
		len |= (header[offset + 2] & 0x00000000000000ff) << 40; 
		len |= (header[offset + 3] & 0x00000000000000ff) << 32;
		len |= (header[offset + 4] & 0x00000000000000ff) << 24;
		len |= (header[offset + 5] & 0x00000000000000ff) << 16;
		len |= (header[offset + 6] & 0x00000000000000ff) << 8;
		len |= (header[offset + 7] & 0x00000000000000ff);
		offset += 8;
	}
	if (mask)
	{
		for (int i = 0; i < 4; i++)
		{
			mask_key[i] = header[offset + i];
		}
		offset += 4;
	}
	return offset;
}

WebSocketProtocolBase::WebSocketProtocolBase()
{
	rbuf_ = new DataRingBuf();
	bIsConnect = false;
}

WebSocketProtocolBase::~WebSocketProtocolBase()
{
	if (rbuf_)
	{
		delete rbuf_;
	}
	bIsConnect = false;
}

int WebSocketProtocolBase::encodeData(const char *data, int len, std::string &dest)
{
	WsHeader wsHeader;
	int headerLen;

	wsHeader.eof = true;
	wsHeader.mask = false;
	wsHeader.opcode = 1;
	wsHeader.len = len;
	headerLen = wsHeader.encode(dest);
	dest.append(data, len);
	//memcpy(dest + headerLen, data, len);
	return headerLen + len;
}

int WebSocketProtocolBase::decodeData(const char *data, int len, std::string &dest, bool &finish)
{
	WsHeader wsHeader;
	int headerLen;
	const char *realData;
	char byte;

	headerLen = wsHeader.decode(data, len);
	realData = data + headerLen;
	if (wsHeader.mask)
	{
		for (int i = 0; i < wsHeader.len; i++)
		{
			byte = realData[i] ^ wsHeader.mask_key[i % 4];
			dest.append(1, byte);
		}
	}
	else
	{
		dest.append(realData, wsHeader.len);
		//memcpy(dest, realData, wsHeader.len);
	}
	finish = wsHeader.eof;
	return wsHeader.len;
}

void WebSocketProtocolBase::close()
{
	bIsConnect = false;
	rbuf_->clear();
}

WebSocketProtocolServer::WebSocketProtocolServer() : WebSocketProtocolBase()
{
	
}

WebSocketProtocolServer::~WebSocketProtocolServer()
{
	std::cout << "delete ws protocol server" << std::endl;
}

int WebSocketProtocolServer::doHandShake(std::string &handshakedata)
{
	int ret;
	std::string handshake;
	char *p;
	const char *data = handshakedata.data();
	int len = handshakedata.length();
	
	if (strstr(data, "\r\n\r\n"))
	{
		ret = rbuf_->getUsed();
		if (ret > 0)
		{
			p = const_cast<char*>(handshake.c_str());
			ret = rbuf_->readData(p, ret);
			handshake = std::string(p, ret) + std::string(data, len);
		}
		else
		{
			handshake = std::string(data, len);
		}
		std::istringstream is(handshake);
		std::string line;
		while (getline(is, line))
		{
			parse_line(line);
		}
		if (upgrade != "websocket" || connection != "Upgrade" || version != "13" || key.empty())
		{
			return -1;
		}
		p = const_cast<char*>(accept.c_str());
		std::string tmp = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		shacalc(tmp.data(), p);
		accept = p;
		return 0;
	}
	else
	{
		ret = rbuf_->writeData(data, len);
		return 1;
	}
}

int WebSocketProtocolServer::doResponse(std::string &responsedata)
{
	std::ostringstream os;
	// 基于当前系统的当前日期/时间
	time_t now = time(0);
	// 把 now 转换为字符串形式
	char* dt = ctime(&now);
	std::string date(dt, strlen(dt) - 1);
	os << protocolVer << " 101 Switching Protocols" << CRLF;
	os << "Connection: " << connection << CRLF;
	os << "Server: " << "WebSocket Server(HeJingsheng)" << CRLF;
	os << "Date: " << date << CRLF;
	os << "Upgrade: " << upgrade << CRLF;
	os << "Sec-WebSocket-Accept: " << accept << CRLF;
	os << CRLF;
	responsedata = os.str();
	bIsConnect = true;
	return 0;
}

void WebSocketProtocolServer::initParam(int method, std::string &path, std::string &host, std::string &extensions)
{
	return;
}

int WebSocketProtocolServer::parse_line(std::string &line)
{
	int ret = 0;
	int i = 0;
	if (line.find(':') == std::string::npos)
	{
		// GET /ajax HTTP/1.1
		std::istringstream is(line);
		std::string tmp;
		while (is >> tmp)
		{
			switch (i)
			{
			case 0:
				if (tmp == "GET")
				{
					method = 0;
				}
				else if (tmp == "POST")
				{
					method = 1;
				}
				else
				{
					return -1;
				}
				break;
			case 1:
				path = tmp;
				break;
			case 2:
				protocolVer = tmp;
				break;
			}
			i++;
		}
	}
	else
	{
		//Connection:Upgrade
		//Host : 127.0.0.1 : 8088
		//Origin : null
		//Sec - WebSocket - Extensions : x - webkit - deflate - frame
		//Sec - WebSocket - Key : puVOuWb7rel6z2AVZBKnfw ==
		//Sec - WebSocket - Version : 13
		//Upgrade : websocket
		parse_attribute(line);
	}
}

int WebSocketProtocolServer::parse_attribute(std::string &line)
{
	std::string attribute = "";
	std::string value = "";
	size_t pos = line.find_first_of(":");
	if (pos != std::string::npos) {
		attribute = line.substr(0, pos);
		value = line.substr(pos + 2);// jump the space ascii
		value = value.substr(0, value.length() - 1);
	}
	if (attribute == "Connection")
	{
		connection = std::move(value);
	}
	else if (attribute == "Host")
	{
		host = std::move(value);
	}
	else if (attribute == "Origin")
	{
		origin = std::move(value);
	}
	else if (attribute == "Sec-WebSocket-Extensions")
	{
		extensions = std::move(value);
	}
	else if (attribute == "Sec-WebSocket-Key")
	{
		key = std::move(value);
	}
	else if (attribute == "Sec-WebSocket-Version")
	{
		version = std::move(value);
	}
	else if (attribute == "Upgrade")
	{
		upgrade = std::move(value);
	}
}

WebSocketProtocolClient::WebSocketProtocolClient()
{

}

WebSocketProtocolClient::~WebSocketProtocolClient()
{

}

int WebSocketProtocolClient::doHandShake(std::string &handshakedata)
{
	std::ostringstream os;
	std::string m;
	if (method == 0)
	{
		m = "GET";
	}
	else
	{
		m = "POST";
	}
	os << m << " " << path << " " << protocolVer << CRLF;
	os << "Host: " << host << CRLF;
	os << "Connection: " << connection << CRLF;
	os << "User-Agent: " << user_agent << CRLF;
	os << "Upgrade: " << upgrade << CRLF;
	os << "Origin: " << origin << CRLF;
	os << "Sec-WebSocket-Version: " << version << CRLF;
	os << "Sec-WebSocket-Key: " << key << CRLF;
	os << "Sec-WebSocket-Extensions: " << extensions << CRLF;
	os << CRLF;
	handshakedata = os.str();
	return 0;
}

int WebSocketProtocolClient::doResponse(std::string &responsedata)
{
	int ret;
	std::string handshake;
	char *p;
	const char *data = responsedata.data();
	int len = responsedata.length();

	if (strstr(data, "\r\n\r\n"))
	{
		ret = rbuf_->getUsed();
		if (ret > 0)
		{
			p = const_cast<char*>(handshake.c_str());
			ret = rbuf_->readData(p, ret);
			handshake = std::string(p, ret) + std::string(data, len);
		}
		else
		{
			handshake = std::string(data, len);
		}
		std::istringstream is(handshake);
		std::string line;
		while (getline(is, line))
		{
			parse_line(line);
		}
		if (upgrade != "websocket" || code != "101" || accept.empty())
		{
			return -1;
		}
		bIsConnect = true;
		return 0;
	}
	else
	{
		ret = rbuf_->writeData(data, len);
		return 1;
	}
}

void WebSocketProtocolClient::initParam(int method, std::string &path, std::string &host, std::string &extensions)
{
	this->method = method;
	this->path = path;
	this->protocolVer = "HTTP/1.1";
	this->host = host;
	this->connection = "Upgrade";
	this->user_agent = "Linux Client";
	this->upgrade = "websocket";
	this->origin = "libuv_ws (HeJingsheng)";
	this->version = "13";
	this->extensions = extensions;
	this->key = generateRandom(24);
	
}

int WebSocketProtocolClient::parse_line(std::string &line)
{
	int ret = 0;
	int i = 0;
	if (line.find(':') == std::string::npos)
	{
		// HTTP/1.1 101 Switching Protocols
		std::istringstream is(line);
		std::string tmp;
		while (is >> tmp)
		{
			switch (i)
			{
			case 0:
				break;
			case 1:
				code = tmp;
				break;
			case 2:
				break;
			}
			i++;
		}
	}
	else
	{
		//Connection:Upgrade
		//Sec - WebSocket - Accept : puVOuWb7rel6z2AVZBKnfw ==
		//Upgrade : websocket
		parse_attribute(line);
	}
}

int WebSocketProtocolClient::parse_attribute(std::string &line)
{
	std::string attribute = "";
	std::string value = "";
	size_t pos = line.find_first_of(":");
	if (pos != std::string::npos) {
		attribute = line.substr(0, pos);
		value = line.substr(pos + 2);// jump the space ascii
		value = value.substr(0, value.length() - 1);
	}
	if (attribute == "Connection")
	{
		connection = std::move(value);
	}
	else if (attribute == "Sec-WebSocket-Accept")
	{
		accept = std::move(value);
	}
	else if (attribute == "Upgrade")
	{
		upgrade = std::move(value);
	}
}