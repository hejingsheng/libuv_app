#ifndef _WS_PROTOCOL_H_
#define _WS_PROTOCOL_H_

#include "DataBuf.h"

const std::string CRLF = "\r\n";
const uint16_t MAX_UINT16 = 65535;

//rfc6455
struct WsHeader
{
	bool eof;
	int opcode;
	bool mask;
	char mask_key[4];
	uint64_t len;

	WsHeader() :eof(false), opcode(0), mask(false), len(0)
	{ 
		mask_key[0] = mask_key[1] = mask_key[2] = mask_key[3] = 0x00;
	}
	
	//return header's length
	int encode(std::string &header);
	int decode(const char *header, int length);
};

class WebSocketProtocolBase
{
public:
	WebSocketProtocolBase();
	virtual ~WebSocketProtocolBase();

public:
	virtual int doHandShake(std::string &handshakedata) = 0;
	virtual int doResponse(std::string &responsedata) = 0;
	int encodeData(const char *data, int len, std::string &dest);
	int decodeData(const char *data, int len, std::string &dest, bool &finish);
	bool isConnected() const { return bIsConnect; }
	void close();
public:
	virtual void initParam(int method, std::string &path, std::string &host, std::string &extensions) = 0;

protected:
	//DataRingBuf *rbuf_;

	int method;   //0 GET  1 POST
	std::string path;
	std::string protocolVer;
	std::string connection;
	std::string host;
	std::string origin;
	std::string extensions;
	std::string key;
	std::string version;
	std::string upgrade;
	std::string accept;

	bool bIsConnect;

};

class WebSocketProtocolServer : public WebSocketProtocolBase
{
public:
	WebSocketProtocolServer();
	virtual ~WebSocketProtocolServer();

public:
	// 0 success -1 fail  1 processing
	virtual int doHandShake(std::string &handshakedata);
	virtual int doResponse(std::string &responsedata);
	virtual void initParam(int method, std::string &path, std::string &host, std::string &extensions);
	
private:
	int parse_line(std::string &line);
	int parse_attribute(std::string &line);
};

class WebSocketProtocolClient : public WebSocketProtocolBase
{
public:
	WebSocketProtocolClient();
	virtual ~WebSocketProtocolClient();

public:
	virtual int doHandShake(std::string &handshakedata);
	virtual int doResponse(std::string &responsedata);
	virtual void initParam(int method, std::string &path, std::string &host, std::string &extensions);

private:
	int parse_line(std::string &line);
	int parse_attribute(std::string &line);

private:
	std::string user_agent;
	std::string code;
};

#endif