#ifndef STREAM_SECURITY_CERTIFICATE_HPP
#define STREAM_SECURITY_CERTIFICATE_HPP

#include "Key.hpp"

namespace Stream::Security {

/**
 * @brief	X509 formatted certificate class
 * @class	Certificate Certificate.hpp "StreamSecurity/Certificate.hpp"
 */
class Certificate {
	std::unique_ptr<X509, decltype(&X509_free)> mVal {nullptr, X509_free};

	explicit Certificate(X509* val);

public:
	struct Exception : std::system_error {
		using std::system_error::system_error;
		enum class Code : int {};
	};//struct Stream::Security::Certificate::Exception

	Certificate(Certificate const& other);

	explicit Certificate(Input& input);

	explicit operator X509*() const noexcept;

	friend Output&
	operator<<(Output& output, Certificate const& certificate);
};//class Stream::Security::Certificate

std::error_code
make_error_code(Certificate::Exception::Code e) noexcept;

}//namespace Stream::Security

namespace std {

template <>
struct is_error_code_enum<Stream::Security::Certificate::Exception::Code> : true_type {};

}//namespace std

#endif //STREAM_SECURITY_CERTIFICATE_HPP
