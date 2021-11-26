/*
Copyright © 2017-2020, orcaer@yeah.net  All rights reserved.

Author: orcaer@yeah.net

Last modified: 2019-12-31

Description: https://github.com/wlgq2/uv-cpp
*/

#include "include/TcpConnection.hpp"
#include "include/TcpServer.hpp"
#include "include/Async.hpp"
#include "include/LogWriter.hpp"
#include "include/GlobalConfig.hpp"

using namespace std;
using namespace std::chrono;
using namespace uv;

struct WriteReq
{
    uv_write_t req;
    uv_buf_t buf;
    AfterWriteCallback callback;
};

struct WriteArgs
{
    WriteArgs(shared_ptr<TcpConnection> conn = nullptr, const char* buf = nullptr, ssize_t size = 0, AfterWriteCallback callback = nullptr)
        :connection(conn),
        buf(buf),
        size(size),
        callback(callback)
    {

    }
    shared_ptr<TcpConnection> connection;
    const char* buf;
    ssize_t size;
    AfterWriteCallback callback;
};

TcpConnection:: ~TcpConnection()
{
	uv::LogWriter::Instance()->debug("destroy tcp connection");
	if (ssl_)
	{
		SSL_free(ssl_);
		ssl_ = NULL;
	}
	if (ctx_)
	{
		SSL_CTX_free(ctx_);
		ctx_ = NULL;
	}
}

TcpConnection::TcpConnection(EventLoop* loop, std::string& name, UVTcpPtr client, bool istls, bool isConnected)
    :name_(name),
    connected_(isConnected),
	tls_(istls),
	tlsStatus_(false),
    loop_(loop),
    handle_(client),
    buffer_(nullptr),
    onMessageCallback_(nullptr),
    onConnectCloseCallback_(nullptr),
    closeCompleteCallback_(nullptr)
{
    handle_->data = static_cast<void*>(this);
    ::uv_read_start((uv_stream_t*)handle_.get(),
        [](uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
    {
        auto conn = static_cast<TcpConnection*>(handle->data);
        buf->base = conn->resizeData(suggested_size);
#if _MSC_VER
        buf->len = (ULONG)suggested_size;
#else
        buf->len = suggested_size;
#endif
    },
        &TcpConnection::onMesageReceive);
    if (GlobalConfig::BufferModeStatus == GlobalConfig::ListBuffer)
    {
        buffer_ = std::make_shared<ListBuffer>();
    }
    else if(GlobalConfig::BufferModeStatus == GlobalConfig::CycleBuffer)
    {
        buffer_ = std::make_shared<CycleBuffer>();
    }
}

int TcpConnection::init(std::string cert, std::string key, TLSRole role)
{
	int ret = 0;
	if (tls_)
	{
		if (role == TLSServer)
		{
			ret = initTlsServer(cert, key);
		}
		else if (role == TLSClient)
		{
			ret = initTlsClient();
		}
		else
		{
			ret = 0;
		}
	}
	return ret;
}

int TcpConnection::initTlsServer(std::string cert, std::string key)
{
	int ret;
#if (OPENSSL_VERSION_NUMBER < 0x10002000L) // v1.0.2
	ctx_ = SSL_CTX_new(TLS_method());
#else
	ctx_ = SSL_CTX_new(TLSv1_2_method());
#endif
	if (ctx_ == NULL)
	{
		ERR_print_errors_fp(stdout);
		uv::LogWriter::Instance()->error("create ssl ctx fail no memery");
		ret = -1;
		goto ERROR;
	}
	SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, NULL);

	//ret = SSL_use_certificate_file(ssl_, cert.c_str(), SSL_FILETYPE_PEM);
	//加载证书和私钥
	if (0 == SSL_CTX_use_certificate_file(ctx_, cert.c_str(), SSL_FILETYPE_PEM))
	{
		ERR_print_errors_fp(stderr);
		ret = -1;
		goto ERROR;
	}
	if (0 == SSL_CTX_use_PrivateKey_file(ctx_, key.c_str(), SSL_FILETYPE_PEM))
	{
		ERR_print_errors_fp(stderr);
		ret = -1;
		goto ERROR;
	}
	if (!SSL_CTX_check_private_key(ctx_))
	{
		printf("Private key does not match the certificate public key\n");
		ret = -1;
		goto ERROR;
	}
	ret = SSL_CTX_set_cipher_list(ctx_, "ALL");
	if (ret != 1)
	{
		uv::LogWriter::Instance()->error("SSL_CTX_set_cipher_list fail");
		ret = -1;
		goto ERROR;
	}
	SSL_CTX_set_mode(ctx_, SSL_MODE_AUTO_RETRY);

	ssl_ = SSL_new(ctx_);
	rbio_ = BIO_new(BIO_s_mem());
	if (rbio_ == NULL)
	{
		uv::LogWriter::Instance()->error("BIO_new r fail");
		ret = -1;
		goto ERROR;
	}
	wbio_ = BIO_new(BIO_s_mem());
	if (wbio_ == NULL)
	{
		uv::LogWriter::Instance()->error("BIO_new w fail");
		ret = -1;
		goto ERROR;
	}
	SSL_set_bio(ssl_, rbio_, wbio_);
	SSL_set_accept_state(ssl_);
	SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE);
ERROR:
	return ret;
}

int TcpConnection::initTlsClient()
{
	int ret = 0;
	ctx_ = SSL_CTX_new(TLSv1_2_client_method());
	if (ctx_ == NULL)
	{
		uv::LogWriter::Instance()->error("create ssl ctx fail no memery");
		return -1;
	}
	ssl_ = SSL_new(ctx_);
	if (ssl_ == NULL)
	{
		uv::LogWriter::Instance()->warn("create ssl fail no memery");
		return -1;
	}
	rbio_ = BIO_new(BIO_s_mem());
	wbio_ = BIO_new(BIO_s_mem());
	SSL_set_bio(ssl_, rbio_, wbio_);
	SSL_set_connect_state(ssl_);
	ret = SSL_connect(ssl_);
	if (ret == 1)
	{
		tlsStatus_ = true;
		return 0;
	}
	else
	{
		send_bio_data();
		int err = SSL_get_error(ssl_, ret);
		if (err == SSL_ERROR_WANT_WRITE)
		{
			send_bio_data();
			ret = 1;
		}
		else if (err == SSL_ERROR_WANT_READ)
		{
			//send_bio_data();
			ret = 1;
		}
		else
		{
			//ERR_print_errors(errBio);
			uv::LogWriter::Instance()->error("ssl connect fail");
			ret = -1;
		}
	}
	return ret;
}

void TcpConnection::send_bio_data()
{
	char *data = NULL;
	int len;

	len = BIO_get_mem_data(wbio_, &data);
	if (data != NULL && len > 0)
	{
		BIO_reset(rbio_);
		write(data, len, nullptr);
		BIO_reset(wbio_);
	}
}

void TcpConnection::onMessage(const char* buf, ssize_t size)
{
	if (tls_)
	{
		if (tlsStatus_)
		{
			int ret;
			ret = BIO_write(rbio_, buf, size);
			ret = SSL_read(ssl_, (void*)buf, size);
			if (ret <= 0)
			{
				int err = SSL_get_error(ssl_, ret);
				if (err == SSL_ERROR_WANT_READ)
				{
					// 在read回调函数中读取数据
				}
				else if (err == SSL_ERROR_WANT_WRITE)
				{
					send_bio_data();
				}
				else
				{
					if (onConnectCloseCallback_)
					{
						onConnectCloseCallback_(name_);
					}
				}
			}
			else
			{
				if (onMessageCallback_)
					onMessageCallback_(shared_from_this(), buf, ret);
			}
		}
		else
		{
			int r0;
			int r1;
			BIO_write(rbio_, buf, size);
			r0 = SSL_do_handshake(ssl_);
			r1 = SSL_get_error(ssl_, r0);
			if (r0 != 1)
			{
				switch (r1)
				{
				case SSL_ERROR_NONE: //0
				case SSL_ERROR_SSL:  // 1
					ERR_print_errors_fp(stderr);
					//don't break, flush data first
				case SSL_ERROR_WANT_READ: // 2
				case SSL_ERROR_WANT_WRITE: // 3
				case SSL_ERROR_WANT_X509_LOOKUP:  // 4
				{
					send_bio_data();
				}
				break;
				case SSL_ERROR_ZERO_RETURN: // 5
				case SSL_ERROR_SYSCALL: //6
				case SSL_ERROR_WANT_CONNECT: //7
				case SSL_ERROR_WANT_ACCEPT: //8
					ERR_print_errors_fp(stderr);
				default:
					break;
				}
			}
			if (r0 == 1)
			{
				send_bio_data();
				tlsStatus_ = true;
				if (onMessageCallback_)
					onMessageCallback_(shared_from_this(), nullptr, 0);
			}
		}
	}
	else
	{
		if (onMessageCallback_)
			onMessageCallback_(shared_from_this(), buf, size);
	}
}

void TcpConnection::onSocketClose()
{
    if (onConnectCloseCallback_)
        onConnectCloseCallback_(name_);
}

void TcpConnection::close(std::function<void(std::string&)> callback)
{
    onMessageCallback_ = nullptr;
    onConnectCloseCallback_ = nullptr;
    closeCompleteCallback_ = nullptr;

    closeCompleteCallback_ = callback;
    uv_tcp_t* ptr = handle_.get();
	if (tls_)
	{
		if (ssl_) {
			// this function will free bio_in and bio_out
			SSL_free(ssl_);
			ssl_ = NULL;
		}
		if (ctx_)
		{
			SSL_CTX_free(ctx_);
			ctx_ = NULL;
		}
		tlsStatus_ = false;
	}
    if (::uv_is_active((uv_handle_t*)ptr))
    {
        ::uv_read_stop((uv_stream_t*)ptr);
    }
    if (::uv_is_closing((uv_handle_t*)ptr) == 0)
    {
        //libuv 在loop轮询中会检测关闭句柄，delete会导致程序异常退出。
        ::uv_close((uv_handle_t*)ptr,
            [](uv_handle_t* handle)
        {
            auto connection = static_cast<TcpConnection*>(handle->data);
            connection->CloseComplete();
        });
    }
    else
    {
        CloseComplete();
    }
}

int TcpConnection::write(const char* buf, ssize_t size, AfterWriteCallback callback)
{
    int rst;
    if (connected_)
    {
        WriteReq* req = new WriteReq;
        req->buf = uv_buf_init(const_cast<char*>(buf), static_cast<unsigned int>(size));
        req->callback = callback;
        auto ptr = handle_.get();
        rst = ::uv_write((uv_write_t*)req, (uv_stream_t*)ptr, &req->buf, 1,
            [](uv_write_t *req, int status)
        {
            WriteReq* wr = (WriteReq*)req;
            if (nullptr != wr->callback)
            {
                struct WriteInfo info;
                info.buf = const_cast<char*>(wr->buf.base);
                info.size = wr->buf.len;
                info.status = status;
                wr->callback(info);
            }
            delete wr;
        });
        if (0 != rst)
        {
            uv::LogWriter::Instance()->error(std::string("write data error:"+std::to_string(rst)));
            if (nullptr != callback)
            {
                struct WriteInfo info = { rst,const_cast<char*>(buf),static_cast<unsigned long>(size) };
                callback(info);
            }
            delete req;
        }
    }
    else
    {
        rst = -1;
        if (nullptr != callback)
        {
            struct WriteInfo info = { WriteInfo::Disconnected,const_cast<char*>(buf),static_cast<unsigned long>(size) };
            callback(info);
        }
    }
    return rst;
}

void TcpConnection::writeInLoop(const char* buf, ssize_t size, AfterWriteCallback callback)
{
    std::weak_ptr<uv::TcpConnection> conn = shared_from_this();
    loop_->runInThisLoop(
        [conn,buf,size, callback]()
    {
        std::shared_ptr<uv::TcpConnection> ptr = conn.lock();
        if (ptr != nullptr)
        {
            ptr->write(buf, size, callback);
        }
        else
        {
            struct WriteInfo info = { WriteInfo::Disconnected,const_cast<char*>(buf),static_cast<unsigned long>(size) };
            callback(info);
        }
    });
}

void TcpConnection::writeTls(const char* buf, ssize_t size, AfterWriteCallback callback)
{
	int err;
	char *data = NULL;
	int len;
	SSL_write(ssl_, buf, size);
	len = BIO_get_mem_data(wbio_, &data);
	if (len > 0 && data != NULL)
	{
		writeInLoop(data, len, callback);
		BIO_reset(wbio_);
	}
	else
	{

	};
}


void TcpConnection::setWrapper(ConnectionWrapperPtr wrapper)
{
    wrapper_ = wrapper;
}

std::shared_ptr<ConnectionWrapper> TcpConnection::getWrapper()
{
    return wrapper_.lock();
}

void  TcpConnection::onMesageReceive(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf)
{
    auto connection = static_cast<TcpConnection*>(client->data);
    if (nread > 0)
    {
        connection->onMessage(buf->base, nread);
    }
    else if (nread < 0)
    {
        connection->setConnectStatus(false);
        uv::LogWriter::Instance()->error( uv_err_name((int)nread));

        if (nread != UV_EOF)
        {
            connection->onSocketClose();
            return;
        }

        uv_shutdown_t* sreq = new uv_shutdown_t;
        sreq->data = static_cast<void*>(connection);
        ::uv_shutdown(sreq, (uv_stream_t*)client,
            [](uv_shutdown_t* req, int status)
        {
            auto connection = static_cast<TcpConnection*>(req->data);
            connection->onSocketClose();
            delete req;
        });
    }
    else
    {
        /* Everything OK, but nothing read. */
    }

}

void uv::TcpConnection::setMessageCallback(OnMessageCallback callback)
{
    onMessageCallback_ = callback;
}

void uv::TcpConnection::setConnectCloseCallback(OnCloseCallback callback)
{
    onConnectCloseCallback_ = callback;
}

void uv::TcpConnection::CloseComplete()
{
    if (closeCompleteCallback_)
    {
        closeCompleteCallback_(name_);
    }
}

void uv::TcpConnection::setConnectStatus(bool status)
{
    connected_ = status;
}

bool uv::TcpConnection::isConnected()
{
    return connected_;
}

bool uv::TcpConnection::isTlsConnected()
{
	return tlsStatus_;
}

const std::string& uv::TcpConnection::Name()
{
    return name_;
}

char* uv::TcpConnection::resizeData(size_t size)
{
    data_.resize(size);
    return const_cast<char*>(data_.c_str());
}

PacketBufferPtr uv::TcpConnection::getPacketBuffer()
{
    return buffer_;
}
