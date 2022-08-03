#ifndef STREAM_SECURITY_CIPHER_HPP
#define STREAM_SECURITY_CIPHER_HPP

#include "Key.hpp"
#include "Stream/Buffer.hpp"

namespace Stream::Security {

/**
 * @brief	Stream::Input %Cipher decryptor
 * @class	CipherDecrypt Cipher.hpp "StreamSecurity/Cipher.hpp"
 */
class CipherDecrypt : public BufferInput {
	std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> mCtx{nullptr, EVP_CIPHER_CTX_free};
	std::unique_ptr<unsigned char> mTempBeg;
	unsigned char* mTempCurr = nullptr;
	unsigned char const* mTempEnd = nullptr;
	bool mFinalizeWhenNoData = true;

	std::size_t
	readBytes(std::byte* dest, std::size_t size) override;

	void
	init(EVP_CIPHER const* cipher, SecureMemory const& key, std::byte const* iv);

public:
	struct Exception : Input::Exception
	{ using Input::Exception::Exception; };

	CipherDecrypt(EVP_CIPHER const* cipher, SecureMemory const& key, std::byte const* iv, std::size_t buffInitialSize = 0);

	CipherDecrypt(EVP_CIPHER const* cipher, SecureMemory const& key, std::byte const* iv, void const* sourceBuff, std::size_t sourceSize);
	
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
class CipherEncrypt : public BufferOutput {
	std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> mCtx{nullptr, EVP_CIPHER_CTX_free};
	int mExtSize = 0;

	std::size_t
	writeBytes(std::byte const* src, std::size_t size) override;

	void
	init(EVP_CIPHER const* cipher, SecureMemory const& key, std::byte const* iv);

public:
	struct Exception : Output::Exception
	{ using Output::Exception::Exception; };

	CipherEncrypt(EVP_CIPHER const* cipher, SecureMemory const& key, std::byte const* iv, std::size_t buffInitialSize = 0);

	CipherEncrypt(EVP_CIPHER const* cipher, SecureMemory const& key, std::byte const* iv, void* sinkBuff, std::size_t sinkSize);

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

	Cipher(EVP_CIPHER const* decCipher, SecureMemory const& decKey, std::byte const* decIv,
			EVP_CIPHER const* encCipher, SecureMemory const& encKey, std::byte const* encIv,
			std::size_t decBuffInitialSize = 0, std::size_t encBuffInitialSize = 0);

	Cipher(EVP_CIPHER const* decCipher, SecureMemory const& decKey, std::byte const* decIv,
			EVP_CIPHER const* encCipher, SecureMemory const& encKey, std::byte const* encIv,
			std::size_t decBuffInitialSize, void* sinkBuff, std::size_t sinkSize);

	Cipher(EVP_CIPHER const* decCipher, SecureMemory const& decKey, std::byte const* decIv,
			EVP_CIPHER const* encCipher, SecureMemory const& encKey, std::byte const* encIv,
			void const* sourceBuff, std::size_t sourceSize, std::size_t encBuffInitialSize = 0);

	Cipher(EVP_CIPHER const* decCipher, SecureMemory const& decKey, std::byte const* decIv,
			EVP_CIPHER const* encCipher, SecureMemory const& encKey, std::byte const* encIv,
			void const* sourceBuff, std::size_t sourceSize, void* sinkBuff, std::size_t sinkSize);

	Cipher(EVP_CIPHER const* cipher, SecureMemory const& key, std::byte const* iv,
			std::size_t decBuffInitialSize = 0, std::size_t encBuffInitialSize = 0);

	Cipher(EVP_CIPHER const* cipher, SecureMemory const& key, std::byte const* iv,
			std::size_t decBuffInitialSize, void* sinkBuff, std::size_t sinkSize);

	Cipher(EVP_CIPHER const* cipher, SecureMemory const& key, std::byte const* iv,
			void const* sourceBuff, std::size_t sourceSize, std::size_t encBuffInitialSize = 0);

	Cipher(EVP_CIPHER const* cipher, SecureMemory const& key, std::byte const* iv,
			void const* sourceBuff, std::size_t sourceSize, void* sinkBuff, std::size_t sinkSize);
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
