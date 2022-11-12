#ifndef SECURITY_CERTIFICATE_HPP
#define SECURITY_CERTIFICATE_HPP

#include "Key.hpp"

namespace Security {

/**
 * @brief	X509 formatted certificate class
 * @class	Certificate Certificate.hpp "Security/Certificate.hpp"
 */
class Certificate {
	std::unique_ptr<X509, decltype(&X509_free)> mVal {nullptr, X509_free};

	explicit Certificate(X509* val);

public:
	struct Exception : std::system_error {
		using std::system_error::system_error;
		enum class Code : int {};
	};//struct Security::Certificate::Exception

	Certificate(Certificate const& other);

	explicit Certificate(Stream::Input& input);

	explicit operator X509*() const noexcept;

	friend Stream::Output&
	operator<<(Stream::Output& output, Certificate const& certificate);
};//class Security::Certificate

std::error_code
make_error_code(Certificate::Exception::Code e) noexcept;

}//namespace Security

namespace std {

template <>
struct is_error_code_enum<Security::Certificate::Exception::Code> : true_type {};

}//namespace std

#endif //SECURITY_CERTIFICATE_HPP
