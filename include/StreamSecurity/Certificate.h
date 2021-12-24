#ifndef STREAM_SECURITY_CERTIFICATE_H
#define STREAM_SECURITY_CERTIFICATE_H

#include "Key.h"

namespace Stream::Security {

/**
 * @brief	X509 formatted certificate class
 * @class	Certificate Certificate.h "StreamSecurity/Certificate.h"
 */
class Certificate {
	std::unique_ptr<X509, decltype(&X509_free)> mVal {nullptr, X509_free};

	explicit Certificate(X509* val);
public:
	struct Exception : std::system_error {
		using std::system_error::system_error;
		enum class Code : int {};
	};//struct Exception

	Certificate(Certificate const& other);

	explicit Certificate(Input& input);

	explicit operator X509*() const noexcept;

	friend Output&
	operator<<(Output& output, Certificate const& certificate);
};//class Certificate

std::error_code
make_error_code(Certificate::Exception::Code e) noexcept;

}//namespace Stream::Security

namespace std {

template <>
struct is_error_code_enum<Stream::Security::Certificate::Exception::Code> : true_type {};

}//namespace std

#endif //STREAM_SECURITY_CERTIFICATE_H
