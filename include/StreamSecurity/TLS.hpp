#ifndef STREAM_SECURITY_TLS_HPP
#define STREAM_SECURITY_TLS_HPP

#include "Certificate.hpp"
#include <Stream/Transform.hpp>
#include <openssl/ssl.h>
#include <memory>

namespace Stream::Security {

/**
 * @brief	Stream::Input %TLS decryptor
 * @class	TLSDecrypt TLS.hpp "StreamSecurity/TLS.hpp"
 */
class TLSDecrypt : public TransformInput {
	SSL* mSSL;
	BIO* mInBio;

protected:
	explicit TLSDecrypt(SSL* ssl);

	std::size_t
	readBytes(std::byte* dest, std::size_t size) override;

	virtual void
	wantSendData() = 0;

	void
	recvData();

public:
	struct Exception : Input::Exception
	{ using Input::Exception::Exception; };

	friend void
	swap(TLSDecrypt& a, TLSDecrypt& b) noexcept;

	TLSDecrypt&
	operator=(TLSDecrypt&& other) noexcept;
};//class Stream::Security::TLSDecrypt

/**
 * @brief	Stream::Output %TLS encryptor
 * @class	TLSEncrypt TLS.hpp "StreamSecurity/TLS.hpp"
 */
class TLSEncrypt : public TransformOutput {
	SSL* mSSL;
	BIO* mOutBio;

protected:
	explicit TLSEncrypt(SSL* ssl);

	std::size_t
	writeBytes(std::byte const* src, std::size_t size) override;

	virtual void
	wantRecvData() = 0;

	void
	sendData();

public:
	struct Exception : Output::Exception
	{ using Output::Exception::Exception; };

	friend void
	swap(TLSEncrypt& a, TLSEncrypt& b) noexcept;

	TLSEncrypt&
	operator=(TLSEncrypt&& other) noexcept;

	bool
	shutdown();
};//class Stream::Security::TLSEncrypt

/**
 * @brief Stream::Input / Stream::Output %TLS decryptor and encryptor
 * @class TLS TLS.hpp "StreamSecurity/TLS.hpp"
 */
class TLS : public TLSDecrypt, public TLSEncrypt {
	std::unique_ptr<SSL, decltype(&SSL_free)> mSSL {nullptr, SSL_free};

	explicit TLS(SSL* ssl);

protected:
	void
	wantSendData() override;

	void
	wantRecvData() override;

public:
	struct Exception : std::system_error {
		using std::system_error::system_error;
		enum class Code : int {};
	};//struct Stream::Security::TLS::Exception

	/**
	 * @brief	%TLS %Context
	 * @class	Context TLS.hppStreamSecurity/TLS.hpp"
	 */
	class Context {
		friend class TLS;
		std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> mCtx;
	public:
		explicit Context(SSL_METHOD const* method);

		Context(SSL_METHOD const* method, Certificate const& certificate, PrivateKey const& privateKey);

		void
		addToStore(Certificate const& caCertificate);
	};//class Stream::Security::TLS::Context

	explicit TLS(Context const& ctx);

	friend void
	swap(TLS& a, TLS& b) noexcept;

	TLS&
	operator=(TLS&& other) noexcept;
};//class Stream::Security::TLS

std::error_code
make_error_code(TLS::Exception::Code e) noexcept;

}//namespace Stream::Security

namespace std {

template <>
struct is_error_code_enum<Stream::Security::TLS::Exception::Code> : true_type {};

}//namespace std

#endif //STREAM_SECURITY_TLS_HPP
