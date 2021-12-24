#ifndef STREAM_SECURITY_KEY_H
#define STREAM_SECURITY_KEY_H

#include "Stream/InOut.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <memory>

namespace Stream::Security {

/**
 * @brief	Heap memory clean and delete functor
 * @class	CleanDeleter Key.h "StreamSecurity/Key.h"
 */
class CleanDeleter {
	std::size_t mSize = 0;
public:
	CleanDeleter() noexcept = default;

	CleanDeleter(std::size_t size) noexcept;

	void operator()(void* ptr) const;

	[[nodiscard]] std::size_t
	getSize() const noexcept;
};

/**
 * @brief	unsigned char unique pointer with secure CleanDeleter
 * @typedef	SecureMemory Key.h "StreamSecurity/Key.h"
 */
using SecureMemory = std::unique_ptr<unsigned char, CleanDeleter>;

class PrivateKey;
class PublicKey;

/**
 * @brief	Generic key
 * @class	Key Key.h "StreamSecurity/Key.h"
 */
class Key {
	friend class PrivateKey;
	friend class PublicKey;
protected:
	std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> mVal {nullptr, EVP_PKEY_free};

	Key() noexcept = default;

	explicit Key(EVP_PKEY* val);

public:
	/**
	 * @brief	Diffie-Hellman key sizes
	 */
	enum class DH : int {
		DH3072 		= 3072,
		DH7680 		= 7680,
		DH15360		= 15360
	};//enum class DH

	/**
	 * @brief	DSA key sizes
	 */
	enum class DSA : int {
		DSA3072 	= 3072,
		DSA7680 	= 7680,
		DSA15360	= 15360
	};//enum class RSA

	/**
	 * @brief	Named elliptic curves
	 */
	enum class EC : int {
		secp256k1 	= NID_secp256k1,
		secp384r1 	= NID_secp384r1,
		secp521r1 	= NID_secp521r1,
		prime256v1 	= NID_X9_62_prime256v1,
		sect283k1 	= NID_sect283k1,
		sect283r1 	= NID_sect283r1,
		sect409k1 	= NID_sect409k1,
		sect409r1 	= NID_sect409r1,
		sect571k1 	= NID_sect571k1,
		sect571r1 	= NID_sect571r1
	};//enum class EC

	/**
	 * @brief	RSA key sizes
	 */
	enum class RSA : int {
		RSA3072 	= 3072,
		RSA7680 	= 7680,
		RSA15360	= 15360
	};//enum class RSA

	struct Exception : std::system_error {
		using std::system_error::system_error;
		enum class Code : int {};
	};//struct Exception

	Key(Key const& other);

	Key(PrivateKey const& privateKey);

	Key(PublicKey const& publicKey);

	Key(DH dh);

	Key(DSA dsa);

	Key(EC ec);

	Key(RSA rsa);

	Key(SecureMemory const& hmacKey);

	Key(SecureMemory const& cmacKey, EVP_CIPHER const* cipher);

	explicit operator EVP_PKEY*() const noexcept;
};//class Key

/**
 * @brief	PKCS8 formatted private key
 * @class	PrivateKey Key.h "StreamSecurity/Key.h"
 */
class PrivateKey {
	std::unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)> mVal {nullptr, PKCS8_PRIV_KEY_INFO_free};
public:
	struct Exception : Key::Exception
	{ using Key::Exception::Exception; };

	explicit PrivateKey(Key const& key);

	explicit PrivateKey(Input& input);

	explicit operator PKCS8_PRIV_KEY_INFO*() const noexcept;

	friend Output&
	operator<<(Output& output, PrivateKey const& privateKey);
};//class PrivateKey

/**
 * @brief	X509 formatted public key
 * @class	PublicKey Key.h "StreamSecurity/Key.h"
 */
class PublicKey {
	std::unique_ptr<X509_PUBKEY, decltype(&X509_PUBKEY_free)> mVal {nullptr, X509_PUBKEY_free};
public:
	struct Exception : Key::Exception
	{ using Key::Exception::Exception; };

	explicit PublicKey(Key const& key);

	explicit PublicKey(Input& input);

	explicit operator X509_PUBKEY*() const noexcept;

	friend Output&
	operator<<(Output& output, PublicKey const& publicKey);
};//class PublicKey

/**
 * @brief	DER formatted file info
 * @struct	DerInfo Key.h "StreamSecurity/Key.h"
 */
struct DerInfo {
	long vLength;
	long tlLength;
	unsigned char tl[sizeof(long)+2];

	struct Exception : std::system_error
	{ using std::system_error::system_error; };

	explicit DerInfo(Input& input);
};

std::error_code
make_error_code(Key::Exception::Code e) noexcept;

}//namespace Stream::Security

namespace std {

template <>
struct is_error_code_enum<Stream::Security::Key::Exception::Code> : true_type {};

}//namespace std

#endif //STREAM_SECURITY_KEY_H
