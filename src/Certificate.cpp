#include "Security/Certificate.hpp"
#include <openssl/err.h>
#include <cstring>

#define ExpectInitialized(x) if (!x) throw Exception(static_cast<Exception::Code>(ERR_peek_last_error()))
#define Expect1(x) if (1 != x) throw Exception(static_cast<Exception::Code>(ERR_peek_last_error()))
#define ExpectPos(x) if (0 >= x) throw Certificate::Exception(static_cast<Certificate::Exception::Code>(ERR_peek_last_error()))

namespace Security {

Certificate::Certificate(X509* val)
		: mVal(val, X509_free)
{ ExpectInitialized(mVal); }

Certificate::Certificate(Certificate const& other)
		: Certificate(X509_dup(static_cast<X509*>(other)))
{}

Certificate::operator X509*() const noexcept
{ return mVal.get(); }

Certificate::Certificate(Stream::Input& input)
{
	DerInfo i(input);

	std::unique_ptr<unsigned char> cert(new unsigned char[i.tlLength + i.vLength]);
	std::memcpy(cert.get(), i.tl, i.tlLength);
	input.read(cert.get() + i.tlLength, i.vLength);

	auto const* in = cert.get();
	mVal.reset(d2i_X509(nullptr, &in, i.tlLength + i.vLength));
	ExpectInitialized(mVal);
}

Stream::Output&
operator<<(Stream::Output& output, Certificate const& certificate)
{
	int length = i2d_X509(static_cast<X509*>(certificate), nullptr);
	ExpectPos(length);
	std::unique_ptr<unsigned char> cert(new unsigned char[length]);

	auto* p = cert.get();
	length = i2d_X509(static_cast<X509*>(certificate), &p);
	ExpectPos(length);
	return output.write(cert.get(), length);
}

std::error_code
make_error_code(Certificate::Exception::Code e) noexcept
{
	static struct : std::error_category {
		[[nodiscard]] char const*
		name() const noexcept override
		{ return "Security::Certificate"; }

		[[nodiscard]] std::string
		message(int ev) const noexcept override
		{ return ERR_error_string(ev, nullptr); }
	} instance;
	return {static_cast<int>(e), instance};
}

}//namespace Security