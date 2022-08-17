#include "StreamSecurity/Cipher.hpp"
#include <cstring>
#include <new>
#include <openssl/err.h>
#include <openssl/rand.h>

#define ExpectAllocated(x) if (!x) throw std::bad_alloc()
#define Expect1(x) if (1 != x) throw Exception(static_cast<Cipher::Exception::Code>(ERR_peek_last_error()))

namespace Stream::Security {

CipherDecrypt::CipherDecrypt(EVP_CIPHER const* cipher, Secret<> const& key, std::byte const* iv)
		: mCtx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free)
{
	ExpectAllocated(mCtx);
	init(cipher, key, iv);
}

CipherDecrypt::CipherDecrypt(CipherDecrypt&& other) noexcept
{ swap(*this, other); }

void
swap(CipherDecrypt& a, CipherDecrypt& b) noexcept
{
	swap(static_cast<TransformInput&>(a), static_cast<TransformInput&>(b));
	std::swap(a.mCtx, b.mCtx);
	std::swap(a.mTempBeg, b.mTempBeg);
	std::swap(a.mTempCurr, b.mTempCurr);
	std::swap(a.mTempEnd, b.mTempEnd);
	std::swap(a.mFinalizeWhenNoData, b.mFinalizeWhenNoData);
}

CipherDecrypt&
CipherDecrypt::operator=(CipherDecrypt&& other) noexcept
{
	swap(*this, other);
	return *this;
}

void
CipherDecrypt::init(EVP_CIPHER const* cipher, Secret<> const& key, std::byte const* iv)
{
	if (EVP_CIPHER_block_size(cipher) > 1)
		mTempBeg.reset(new unsigned char[2*EVP_CIPHER_block_size(cipher)]);

	/*
	if (EVP_CIPHER_mode(cipher) == EVP_CIPH_WRAP_MODE)
		EVP_CIPHER_CTX_set_flags(mCtx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
	*/

	Expect1(EVP_DecryptInit_ex(mCtx.get(), cipher, nullptr, key.get(), reinterpret_cast<unsigned char const*>(iv)));
}

std::size_t
CipherDecrypt::readBytes(std::byte* dest, std::size_t size)
{
	if (mTempCurr != mTempEnd) { // there is decrypted data
		if (size > mTempEnd - mTempCurr)
			size = mTempEnd - mTempCurr;
		std::memcpy(dest, mTempCurr, size);
		mTempCurr += size;
		return size;
	}

	if (!EVP_CIPHER_CTX_cipher(mCtx.get()))
		throw Exception(Input::Exception::Code::Uninitialized);

	if (EVP_CIPHER_CTX_block_size(mCtx.get()) > 1) {
		if (size >= 2 * EVP_CIPHER_CTX_block_size(mCtx.get())) {
			size /= EVP_CIPHER_CTX_block_size(mCtx.get());
			size = (size - 1) * EVP_CIPHER_CTX_block_size(mCtx.get());
		}
		else {
			size = EVP_CIPHER_CTX_block_size(mCtx.get());
			dest = reinterpret_cast<std::byte*>(mTempBeg.get());
		}
	}

	if (mFinalizeWhenNoData) {
		try {
			size = provideSomeData(size);
		} catch (Input::Exception const& exc) {
			if (exc.code() != std::make_error_code(std::errc::no_message_available))
				throw;
			finalizeDecryption();
			return 0; // try again to read from mTemp
		}
	} else
		size = provideSomeData(size);

	int outl;
	Expect1(EVP_DecryptUpdate(mCtx.get(), reinterpret_cast<unsigned char*>(dest), &outl,
			reinterpret_cast<unsigned char const*>(getData()), static_cast<int>(size)));

	advanceData(size);
	if (dest == reinterpret_cast<std::byte*>(mTempBeg.get())) {
		mTempEnd = (mTempCurr = mTempBeg.get()) + outl;
		return 0; // try again to read from mTemp
	}
	return outl;
}

void
CipherDecrypt::finalizeDecryption()
{
	if (EVP_CIPHER_CTX_cipher(mCtx.get())) {
		if (EVP_CIPHER_CTX_block_size(mCtx.get()) > 1) {
			int outl;
			Expect1(EVP_DecryptFinal_ex(mCtx.get(), mTempBeg.get(), &outl));
			mTempEnd = (mTempCurr = mTempBeg.get()) + outl;
		}
		Expect1(EVP_CIPHER_CTX_reset(mCtx.get()));
	}
}

void
CipherDecrypt::finalizeDecryptionWhenNoData(bool on)
{ mFinalizeWhenNoData = on; }

CipherEncrypt::CipherEncrypt(EVP_CIPHER const* cipher, Secret<> const& key, std::byte const* iv)
		: mCtx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free)
{
	ExpectAllocated(mCtx);
	init(cipher, key, iv);
}

CipherEncrypt::CipherEncrypt(CipherEncrypt&& other) noexcept
{ swap(*this, other); }

void
swap(CipherEncrypt& a, CipherEncrypt& b) noexcept
{
	swap(static_cast<TransformOutput&>(a), static_cast<TransformOutput&>(b));
	std::swap(a.mCtx, b.mCtx);
	std::swap(a.mExtSize, b.mExtSize);
}

CipherEncrypt&
CipherEncrypt::operator=(CipherEncrypt&& other) noexcept
{
	swap(*this, other);
	return *this;
}

void
CipherEncrypt::init(EVP_CIPHER const* cipher, Secret<> const& key, std::byte const* iv)
{
	mExtSize = EVP_CIPHER_block_size(cipher) - 1;
	/*
	if (EVP_CIPHER_mode(cipher) == EVP_CIPH_WRAP_MODE) {
		EVP_CIPHER_CTX_set_flags(mCtx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
		++mExtSize;
	}
	*/

	Expect1(EVP_EncryptInit_ex(mCtx.get(), cipher, nullptr, key.get(), reinterpret_cast<unsigned char const*>(iv)));
}

std::size_t
CipherEncrypt::writeBytes(std::byte const* src, std::size_t size)
{
	if (!EVP_CIPHER_CTX_cipher(mCtx.get()))
		throw Exception(Output::Exception::Code::Uninitialized);

	provideSpace(size + mExtSize);

	int outl;
	Expect1(EVP_EncryptUpdate(mCtx.get(), reinterpret_cast<unsigned char*>(getSpace()), &outl,
			reinterpret_cast<unsigned char const*>(src), static_cast<int>(size)));
	advanceSpace(outl);
	return size;
}

void
CipherEncrypt::finalizeEncryption()
{
	if (EVP_CIPHER_CTX_cipher(mCtx.get())) {
		if (EVP_CIPHER_CTX_block_size(mCtx.get()) > 1) {
			provideSpace(EVP_CIPHER_CTX_block_size(mCtx.get()));
			int outl;
			Expect1(EVP_EncryptFinal_ex(mCtx.get(), reinterpret_cast<unsigned char*>(getSpace()), &outl));
			advanceSpace(outl);
			mExtSize = 0;
		}
		Expect1(EVP_CIPHER_CTX_reset(mCtx.get()));
	}
}

CipherEncrypt::~CipherEncrypt()
{
	try {
		finalizeEncryption();
	} catch (Output::Exception const& exc) {
		::write(STDERR_FILENO, exc.what(), std::strlen(exc.what()));
	}
}

Cipher::Cipher(EVP_CIPHER const* cipher, Secret<> const& key, std::byte const* iv)
		: Cipher(cipher, key, iv, cipher, key, iv)
{}

Cipher::Cipher(EVP_CIPHER const* decCipher, Secret<> const& decKey, std::byte const* decIv,
		EVP_CIPHER const* encCipher, Secret<> const& encKey, std::byte const* encIv)
		: CipherDecrypt(decCipher, decKey, decIv)
		, CipherEncrypt(encCipher, encKey, encIv)
{}

void
swap(Cipher& a, Cipher& b) noexcept
{
	swap(static_cast<CipherDecrypt&>(a), static_cast<CipherDecrypt&>(b));
	swap(static_cast<CipherEncrypt&>(a), static_cast<CipherEncrypt&>(b));
}

std::error_code
make_error_code(Cipher::Exception::Code e) noexcept
{
	static struct : std::error_category {
		[[nodiscard]] char const*
		name() const noexcept override
		{ return "Stream::Security::Cipher"; }

		[[nodiscard]] std::string
		message(int ev) const noexcept override
		{ return ERR_error_string(ev, nullptr); }
	} instance;
	return {static_cast<int>(e), instance};
}

}//namespace Stream::Security
