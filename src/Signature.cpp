#include "StreamSecurity/Signature.hpp"
#include "Stream/Buffer.hpp"
#include <cstring>
#include <openssl/err.h>

#define ExpectAllocated(x) if (!x) throw Exception(Buffer::Exception::Code::BadAllocation)
#define Expect1(x) if (1 != x) throw Exception(static_cast<Signature::Exception::Code>(ERR_peek_last_error()))

namespace Stream::Security {

SignatureInput::SignatureInput(EVP_MD const* md, Key const& verifyKey)
		: mCtx(EVP_MD_CTX_new(), EVP_MD_CTX_free)
{
	ExpectAllocated(mCtx);
	Expect1(EVP_DigestVerifyInit(mCtx.get(), nullptr, md, nullptr, static_cast<EVP_PKEY*>(verifyKey)));
}

SignatureInput::SignatureInput(SignatureInput&& other) noexcept
{ swap(*this, other); }

void
swap(SignatureInput& a, SignatureInput& b) noexcept
{
	swap(static_cast<InputFilter&>(a), static_cast<InputFilter&>(b));
	std::swap(a.mCtx, b.mCtx);
}

SignatureInput&
SignatureInput::operator=(SignatureInput&& other) noexcept
{
	std::swap(mCtx, other.mCtx);
	return *this;
}

std::size_t
SignatureInput::readBytes(std::byte* dest, std::size_t size)
{
	size = mSource->readSome(dest, size);

	Expect1(EVP_DigestVerifyUpdate(mCtx.get(), dest, size));
	return size;
}

bool
SignatureInput::verifySignature(std::vector<std::byte> const& signature) const
{ return Signature::Verify(mCtx.get(), signature); }

SignatureOutput::SignatureOutput(EVP_MD const* md, Key const& signKey)
		: mCtx(EVP_MD_CTX_new(), EVP_MD_CTX_free)
{
	ExpectAllocated(mCtx);
	Expect1(EVP_DigestSignInit(mCtx.get(), nullptr, md, nullptr, static_cast<EVP_PKEY*>(signKey)));
}

SignatureOutput::SignatureOutput(SignatureOutput&& other) noexcept
{ swap(*this, other); }

void
swap(SignatureOutput& a, SignatureOutput& b) noexcept
{
	swap(static_cast<OutputFilter&>(a), static_cast<OutputFilter&>(b));
	std::swap(a.mCtx, b.mCtx);
}

SignatureOutput&
SignatureOutput::operator=(SignatureOutput&& other) noexcept
{
	std::swap(mCtx, other.mCtx);
	return *this;
}

std::size_t
SignatureOutput::writeBytes(std::byte const* src, std::size_t size)
{
	size = mSink->writeSome(src, size);

	Expect1(EVP_DigestSignUpdate(mCtx.get(), src, size));
	return size;
}

std::size_t
SignatureOutput::getSignatureSize() const
{ return Signature::Size(mCtx.get()); }

std::vector<std::byte>
SignatureOutput::getSignature() const
{ return Signature::Sign(mCtx.get()); }

std::size_t
Signature::Size(EVP_MD_CTX* ctx)
{
	std::size_t size = 0;
	Expect1(EVP_DigestSignFinal(ctx, nullptr, &size));
	return size;;
}

std::vector<std::byte>
Signature::Sign(EVP_MD_CTX* ctx)
{
	std::size_t size = Signature::Size(ctx);
	std::vector<std::byte> val;
	val.resize(size);

	Expect1(EVP_DigestSignFinal(ctx, reinterpret_cast<unsigned char*>(val.data()), &size));
	val.resize(size);
	return val;
}

std::vector<std::byte>
Signature::Sign(void const* data, std::size_t count, EVP_MD const* md, Key const& signKey)
{
	std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx{EVP_MD_CTX_new(), EVP_MD_CTX_free};
	ExpectAllocated(ctx);
	Expect1(EVP_DigestSignInit(ctx.get(), nullptr, md, nullptr, static_cast<EVP_PKEY*>(signKey)));
	Expect1(EVP_DigestSignUpdate(ctx.get(), data, count));
	return Signature::Sign(ctx.get());
}

bool
Signature::Verify(EVP_MD_CTX* ctx, std::vector<std::byte> const& signature)
{
	auto result = EVP_DigestVerifyFinal(ctx, reinterpret_cast<unsigned char const*>(signature.data()), signature.size());
	if (result < 0)
		throw Exception(static_cast<Signature::Exception::Code>(ERR_peek_last_error()));
	return result;
}

bool
Signature::Verify(void const* data, std::size_t count, EVP_MD const* md, Key const& verifyKey, std::vector<std::byte> const& signature)
{
	std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx{EVP_MD_CTX_new(), EVP_MD_CTX_free};
	ExpectAllocated(ctx);
	EVP_MD_CTX_set_flags(ctx.get(), EVP_MD_CTX_FLAG_ONESHOT);
	Expect1(EVP_DigestVerifyInit(ctx.get(), nullptr, md, nullptr, static_cast<EVP_PKEY*>(verifyKey)));
	Expect1(EVP_DigestVerifyUpdate(ctx.get(), data, count));
	return Signature::Verify(ctx.get(), signature);
}

Signature::Signature(EVP_MD const* mdIn, Key const& verifyKey, EVP_MD const* mdOut, Key const& signKey)
		: SignatureInput(mdIn, verifyKey)
		, SignatureOutput(mdOut, signKey)
{}

Signature::Signature(EVP_MD const* md, Key const& key)
		: Signature(md, key, md, key)
{}

void
swap(Signature& a, Signature& b) noexcept
{
	swap(static_cast<SignatureInput&>(a), static_cast<SignatureInput&>(b));
	swap(static_cast<SignatureOutput&>(a), static_cast<SignatureOutput&>(b));
}

std::error_code
make_error_code(Signature::Exception::Code e) noexcept
{
	static struct : std::error_category {
		[[nodiscard]] char const*
		name() const noexcept override
		{ return "Stream::Security::Signature"; }

		[[nodiscard]] std::string
		message(int ev) const noexcept override
		{ return ERR_error_string(ev, nullptr); }
	} instance;
	return {static_cast<int>(e), instance};
}

}//namespace Stream::Security
