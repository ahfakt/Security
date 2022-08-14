#include "StreamSecurity/Digest.hpp"
#include <new>
#include <openssl/err.h>

#define ExpectAllocated(x) if (!x) throw std::bad_alloc()
#define Expect1(x) if (1 != x) throw Exception(static_cast<Digest::Exception::Code>(ERR_peek_last_error()))

namespace Stream::Security {

DigestInput::DigestInput(EVP_MD const* md, EVP_PKEY* key)
		: mCtx(EVP_MD_CTX_new(), EVP_MD_CTX_free)
{
	ExpectAllocated(mCtx);
	if (key) {
		Expect1(EVP_DigestSignInit(mCtx.get(), nullptr, md, nullptr, key));
	} else {
		Expect1(EVP_DigestInit_ex(mCtx.get(), md, nullptr));
	}
}

DigestInput::DigestInput(EVP_MD const* md)
		: DigestInput(md, nullptr)
{}

DigestInput::DigestInput(EVP_MD const* md, Key const& key)
		: DigestInput(md, static_cast<EVP_PKEY*>(key))
{}

DigestInput::DigestInput(DigestInput&& other) noexcept
{ swap(*this, other); }

void
swap(DigestInput& a, DigestInput& b) noexcept
{
	swap(static_cast<TransparentInput&>(a), static_cast<TransparentInput&>(b));
	std::swap(a.mCtx, b.mCtx);
}

DigestInput&
DigestInput::operator=(DigestInput&& other) noexcept
{
	swap(*this, other);
	return *this;
}

std::size_t
DigestInput::readBytes(std::byte* dest, std::size_t size)
{
	size = getSome(dest, size);

	if (EVP_MD_CTX_pkey_ctx(mCtx.get())) {
		Expect1(EVP_DigestSignUpdate(mCtx.get(), dest, size));
	} else {
		Expect1(EVP_DigestUpdate(mCtx.get(), dest, size));
	}
	return size;
}

std::size_t
DigestInput::getInputDigestSize() const noexcept
{ return Digest::Size(mCtx.get()); }

std::vector<std::byte>
DigestInput::getInputDigest() const
{ return Digest::Value(mCtx.get()); }

DigestOutput::DigestOutput(EVP_MD const* md, EVP_PKEY* key)
		: mCtx(EVP_MD_CTX_new(), EVP_MD_CTX_free)
{
	ExpectAllocated(mCtx);
	if (key) {
		Expect1(EVP_DigestSignInit(mCtx.get(), nullptr, md, nullptr, key));
	} else {
		Expect1(EVP_DigestInit_ex(mCtx.get(), md, nullptr));
	}
}

DigestOutput::DigestOutput(EVP_MD const* md)
		: DigestOutput(md, nullptr)
{}

DigestOutput::DigestOutput(EVP_MD const* md, Key const& key)
		: DigestOutput(md, static_cast<EVP_PKEY*>(key))
{}

DigestOutput::DigestOutput(DigestOutput&& other) noexcept
{ swap(*this, other); }

void
swap(DigestOutput& a, DigestOutput& b) noexcept
{
	swap(static_cast<TransparentOutput&>(a), static_cast<TransparentOutput&>(b));
	std::swap(a.mCtx, b.mCtx);
}

DigestOutput&
DigestOutput::operator=(DigestOutput&& other) noexcept
{
	swap(*this, other);
	return *this;
}

std::size_t
DigestOutput::writeBytes(std::byte const* src, std::size_t size)
{
	size = putSome(src, size);

	if (EVP_MD_CTX_pkey_ctx(mCtx.get())) {
		Expect1(EVP_DigestSignUpdate(mCtx.get(), src, size));
	} else {
		Expect1(EVP_DigestUpdate(mCtx.get(), src, size));
	}
	return size;
}

std::size_t
DigestOutput::getOutputDigestSize() const noexcept
{ return Digest::Size(mCtx.get()); }

std::vector<std::byte>
DigestOutput::getOutputDigest() const
{ return Digest::Value(mCtx.get()); }

std::size_t
Digest::Size(EVP_MD_CTX* ctx)
{
	std::size_t size = 0;
	if (EVP_MD_CTX_pkey_ctx(ctx)) {
		Expect1(EVP_DigestSignFinal(ctx, nullptr, &size));
		return size;
	}
	return EVP_MD_size(EVP_MD_CTX_md(ctx));
}

std::vector<std::byte>
Digest::Value(EVP_MD_CTX* ctx)
{
	std::size_t size = Digest::Size(ctx);
	std::vector<std::byte> val;
	val.resize(size);

	if (EVP_MD_CTX_pkey_ctx(ctx)) {
		Expect1(EVP_DigestSignFinal(ctx, reinterpret_cast<unsigned char*>(val.data()), &size));
	} else {
		std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctxCopy{EVP_MD_CTX_new(), EVP_MD_CTX_free};
		ExpectAllocated(ctxCopy);
		Expect1(EVP_MD_CTX_copy(ctxCopy.get(), ctx));
		Expect1(EVP_DigestFinal_ex(ctxCopy.get(), reinterpret_cast<unsigned char*>(val.data()), reinterpret_cast<unsigned int*>(&size)));
	}
	val.resize(size);
	return val;
}

std::vector<std::byte>
Digest::Compute(void const* data, std::size_t count, EVP_MD const* md)
{
	std::size_t size = EVP_MD_size(md);
	std::vector<std::byte> val;
	val.resize(size);

	Expect1(EVP_Digest(data, count, reinterpret_cast<unsigned char*>(val.data()), reinterpret_cast<unsigned int*>(&size), md, nullptr));

	val.resize(size);
	return val;
}

std::vector<std::byte>
Digest::Compute(void const* data, std::size_t count, EVP_MD const* md, Key const& key)
{
	std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx{EVP_MD_CTX_new(), EVP_MD_CTX_free};
	ExpectAllocated(ctx);
	Expect1(EVP_DigestSignInit(ctx.get(), nullptr, md, nullptr, static_cast<EVP_PKEY*>(key)));

	std::size_t size = Digest::Size(ctx.get());
	std::vector<std::byte> val;
	val.resize(size);

	Expect1(EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char*>(val.data()), &size, reinterpret_cast<unsigned char const*>(data), count));

	val.resize(size);
	return val;
}

bool
Digest::Matches(std::vector<std::byte> const& digest1, std::vector<std::byte> const& digest2) noexcept
{ return digest1.size() == digest2.size() && 0 == CRYPTO_memcmp(digest1.data(), digest2.data(), digest1.size()); }

Digest::Digest(EVP_MD const* md)
		: Digest(md, md)
{}

Digest::Digest(EVP_MD const* md, Key const& key)
		: Digest(md, key, md, key)
{}

Digest::Digest(EVP_MD const* mdIn, EVP_MD const* mdOut)
		: DigestInput(mdIn)
		, DigestOutput(mdOut)
{}

Digest::Digest(EVP_MD const* mdIn, EVP_MD const* mdOut, Key const& outKey)
		: DigestInput(mdIn)
		, DigestOutput(mdOut, outKey)
{}

Digest::Digest(EVP_MD const* mdIn, Key const& inKey, EVP_MD const* mdOut)
		: DigestInput(mdIn, inKey)
		, DigestOutput(mdOut)
{}

Digest::Digest(EVP_MD const* mdIn, Key const& inKey, EVP_MD const* mdOut, Key const& outKey)
		: DigestInput(mdIn, inKey)
		, DigestOutput(mdOut, outKey)
{}

void
swap(Digest& a, Digest& b) noexcept
{
	swap(static_cast<DigestInput&>(a), static_cast<DigestInput&>(b));
	swap(static_cast<DigestOutput&>(a), static_cast<DigestOutput&>(b));
}

std::error_code
make_error_code(Digest::Exception::Code e) noexcept
{
	static struct : std::error_category {
		[[nodiscard]] char const*
		name() const noexcept override
		{ return "Stream::Security::Digest"; }

		[[nodiscard]] std::string
		message(int ev) const noexcept override
		{ return ERR_error_string(ev, nullptr); }
	} instance;
	return {static_cast<int>(e), instance};
}

}//namespace Stream::Security
