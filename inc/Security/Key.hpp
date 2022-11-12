#ifndef SECURITY_KEY_HPP
#define SECURITY_KEY_HPP

#include <Stream/InOut.hpp>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <memory>

namespace Security {

template <typename T>
struct SecretImpl : std::unique_ptr<T> {
	SecretImpl(SecretImpl&&) noexcept = default;

	explicit SecretImpl(auto&& ... args)
			: std::unique_ptr<T>(::new T{std::forward<decltype(args)>(args) ...})
	{}

	~SecretImpl()
	{
		auto* t = this->release();
		t->~T();
		OPENSSL_cleanse(t, sizeof(T));
		::operator delete(t);
	}

	[[nodiscard]] std::size_t
	size() const noexcept
	{ return sizeof(T); }
};//struct Security::SecretImpl<T>

template <>
struct SecretImpl<unsigned char[]> : std::unique_ptr<unsigned char[]> {
	SecretImpl(SecretImpl&&) noexcept = default;

	explicit SecretImpl(std::size_t size)
			: std::unique_ptr<unsigned char[]>(::new unsigned char[size])
			, mSize(size)
	{}

	~SecretImpl()
	{ OPENSSL_cleanse(get(), mSize); }

	[[nodiscard]] std::size_t
	size() const noexcept
	{ return mSize; }

private:
	std::size_t mSize = 0;
};//class Security::SecretImpl<>

/**
 * @brief	Secure memory buffer
 * @class	Secret Key.hpp "Security/Key.hpp"
 */
template <typename T = unsigned char[]>
using Secret = SecretImpl<T>;

class PrivateKey;
class PublicKey;

/**
 * @brief	Generic key
 * @class	Key Key.hpp "Security/Key.hpp"
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
	};//enum class Security::Key::DH

	/**
	 * @brief	DSA key sizes
	 */
	enum class DSA : int {
		DSA3072 	= 3072,
		DSA7680 	= 7680,
		DSA15360	= 15360
	};//enum class Security::Key::RSA

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
	};//enum class Security::Key::EC

	/**
	 * @brief	RSA key sizes
	 */
	enum class RSA : int {
		RSA3072 	= 3072,
		RSA7680 	= 7680,
		RSA15360	= 15360
	};//enum class Security::Key::RSA

	struct Exception : std::system_error {
		using std::system_error::system_error;
		enum class Code : int {};
	};//struct Security::Key::Exception

	Key(Key const& other);

	Key(PrivateKey const& privateKey);

	Key(PublicKey const& publicKey);

	Key(DH dh);

	Key(DSA dsa);

	Key(EC ec);

	Key(RSA rsa);

	Key(Secret<> const& hmacKey);

	Key(Secret<> const& cmacKey, EVP_CIPHER const* cipher);

	explicit operator EVP_PKEY*() const noexcept;
};//class Security::Key

/**
 * @brief	PKCS8 private key
 * @class	PrivateKey Key.hpp "Security/Key.hpp"
 */
class PrivateKey {
	std::unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)> mVal {nullptr, PKCS8_PRIV_KEY_INFO_free};
public:
	struct Exception : Key::Exception
	{ using Key::Exception::Exception; };

	explicit PrivateKey(Key const& key);

	explicit PrivateKey(Stream::Input& input);

	explicit operator PKCS8_PRIV_KEY_INFO*() const noexcept;

	friend Stream::Output&
	operator<<(Stream::Output& output, PrivateKey const& privateKey);
};//class Security::PrivateKey

/**
 * @brief	X509 public key
 * @class	PublicKey Key.hpp "Security/Key.hpp"
 */
class PublicKey {
	std::unique_ptr<X509_PUBKEY, decltype(&X509_PUBKEY_free)> mVal {nullptr, X509_PUBKEY_free};
public:
	struct Exception : Key::Exception
	{ using Key::Exception::Exception; };

	explicit PublicKey(Key const& key);

	explicit PublicKey(Stream::Input& input);

	explicit operator X509_PUBKEY*() const noexcept;

	friend Stream::Output&
	operator<<(Stream::Output& output, PublicKey const& publicKey);
};//class Security::PublicKey

/**
 * @brief	DER formatted file info
 * @struct	DerInfo Key.hpp "Security/Key.hpp"
 */
struct DerInfo {
	long vLength;
	long tlLength;
	unsigned char tl[sizeof(long)+2];

	struct Exception : std::system_error
	{ using std::system_error::system_error; };

	explicit DerInfo(Stream::Input& input);
};//struct Security::DerInfo

std::error_code
make_error_code(Key::Exception::Code e) noexcept;

}//namespace Security

namespace std {

template <>
struct is_error_code_enum<Security::Key::Exception::Code> : true_type {};

}//namespace std

#endif //SECURITY_KEY_HPP
