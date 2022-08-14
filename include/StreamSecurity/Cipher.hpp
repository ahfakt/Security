#ifndef STREAM_SECURITY_CIPHER_HPP
#define STREAM_SECURITY_CIPHER_HPP

#include "Key.hpp"
#include <Stream/Transform.hpp>

namespace Stream::Security {

/**
 * @brief	Stream::Input %Cipher decryptor
 * @class	CipherDecrypt Cipher.hpp "StreamSecurity/Cipher.hpp"
 */
class CipherDecrypt : public TransformInput {
	std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> mCtx{nullptr, EVP_CIPHER_CTX_free};
	std::unique_ptr<unsigned char> mTempBeg;
	unsigned char* mTempCurr = nullptr;
	unsigned char const* mTempEnd = nullptr;
	bool mFinalizeWhenNoData = true;

	std::size_t
	readBytes(std::byte* dest, std::size_t size) override;

	void
	init(EVP_CIPHER const* cipher, Secret<> const& key, std::byte const* iv);

public:
	struct Exception : Input::Exception
	{ using Input::Exception::Exception; };

	CipherDecrypt(EVP_CIPHER const* cipher, Secret<> const& key, std::byte const* iv);
	
	CipherDecrypt(CipherDecrypt&& other) noexcept;

	friend void
	swap(CipherDecrypt& a, CipherDecrypt& b) noexcept;

	CipherDecrypt&
	operator=(CipherDecrypt&& other) noexcept;

	void
	finalizeDecryption();

	void
	finalizeDecryptionWhenNoData(bool on = true);
};//class Stream::Security::CipherDecrypt

/**
 * @brief	Stream::Output %Cipher encryptor
 * @class	CipherEncrypt Cipher.hpp "StreamSecurity/Cipher.hpp"
 */
class CipherEncrypt : public TransformOutput {
	std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> mCtx{nullptr, EVP_CIPHER_CTX_free};
	int mExtSize = 0;

	std::size_t
	writeBytes(std::byte const* src, std::size_t size) override;

	void
	init(EVP_CIPHER const* cipher, Secret<> const& key, std::byte const* iv);

public:
	struct Exception : Output::Exception
	{ using Output::Exception::Exception; };

	CipherEncrypt(EVP_CIPHER const* cipher, Secret<> const& key, std::byte const* iv);

	CipherEncrypt(CipherEncrypt&& other) noexcept;

	friend void
	swap(CipherEncrypt& a, CipherEncrypt& b) noexcept;

	CipherEncrypt&
	operator=(CipherEncrypt&& other) noexcept;

	~CipherEncrypt();

	void
	finalizeEncryption();
};//class Stream::Security::CipherEncrypt

/**
 * @brief Stream::Input / Stream::Output %Cipher decryptor and encryptor
 * @class Cipher Cipher.hpp "StreamSecurity/Cipher.hpp"
 */
class Cipher : public CipherDecrypt, public CipherEncrypt {
public:
	struct Exception {
		enum class Code : int {};
	};//struct Stream::Security::Cipher::Exception

	Cipher(EVP_CIPHER const* cipher, Secret<> const& key, std::byte const* iv);

	Cipher(EVP_CIPHER const* decCipher, Secret<> const& decKey, std::byte const* decIv,
			EVP_CIPHER const* encCipher, Secret<> const& encKey, std::byte const* encIv);
};//class Stream::Security::Cipher

void
swap(Cipher& a, Cipher& b) noexcept;

std::error_code
make_error_code(Cipher::Exception::Code e) noexcept;

}//namespace Stream::Security

namespace std {

template <>
struct is_error_code_enum<Stream::Security::Cipher::Exception::Code> : true_type {};

}//namespace std

#endif //STREAM_SECURITY_CIPHER_HPP
