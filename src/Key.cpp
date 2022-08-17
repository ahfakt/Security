#include "StreamSecurity/Key.hpp"
#include <openssl/err.h>
#include <cstring>

#define ExpectInitialized(x) if (!x) throw Exception(static_cast<Exception::Code>(ERR_peek_last_error()))
#define Expect1(x) if (1 != x) throw Exception(static_cast<Exception::Code>(ERR_peek_last_error()))
#define ExpectPos(x) if (0 >= x) throw Key::Exception(static_cast<Key::Exception::Code>(ERR_peek_last_error()))

namespace Stream::Security {

Key::Key(EVP_PKEY* val)
		: mVal(val, EVP_PKEY_free)
{ ExpectInitialized(mVal); }

Key::Key(Key const& other)
		: Key(other.mVal.get())
{ Expect1(EVP_PKEY_up_ref(mVal.get())); }

Key::Key(PrivateKey const& privateKey)
		: Key(EVP_PKCS82PKEY(static_cast<PKCS8_PRIV_KEY_INFO*>(privateKey)))
{}

Key::Key(PublicKey const& publicKey)
		: Key(X509_PUBKEY_get(static_cast<X509_PUBKEY*>(publicKey)))
{}

Key::Key(DH dh)
{
	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx{EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr), EVP_PKEY_CTX_free};
	ExpectInitialized(pctx);
	Expect1(EVP_PKEY_paramgen_init(pctx.get()));
	ExpectPos(EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx.get(), static_cast<int>(dh)));

	EVP_PKEY* params = nullptr;
	Expect1(EVP_PKEY_paramgen(pctx.get(), &params));
	std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> _{params, EVP_PKEY_free};

	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> kctx{EVP_PKEY_CTX_new(params, nullptr), EVP_PKEY_CTX_free};
	ExpectInitialized(kctx);
	Expect1(EVP_PKEY_keygen_init(kctx.get()));
	EVP_PKEY* k = nullptr;
	Expect1(EVP_PKEY_keygen(kctx.get(), &k));
	mVal.reset(k);
}

Key::Key(DSA dsa)
{
	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx{EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, nullptr), EVP_PKEY_CTX_free};
	ExpectInitialized(pctx);
	Expect1(EVP_PKEY_paramgen_init(pctx.get()));
	ExpectPos(EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx.get(), static_cast<int>(dsa)));

	EVP_PKEY* params = nullptr;
	Expect1(EVP_PKEY_paramgen(pctx.get(), &params));
	std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> _{params, EVP_PKEY_free};

	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> kctx{EVP_PKEY_CTX_new(params, nullptr), EVP_PKEY_CTX_free};
	ExpectInitialized(kctx);
	Expect1(EVP_PKEY_keygen_init(kctx.get()));
	EVP_PKEY* k = nullptr;
	Expect1(EVP_PKEY_keygen(kctx.get(), &k));
	mVal.reset(k);
}

Key::Key(EC ecNid)
{
	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> kctx{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free};
	ExpectInitialized(kctx);
	Expect1(EVP_PKEY_keygen_init(kctx.get()));
	ExpectPos(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx.get(), static_cast<int>(ecNid)));
	EVP_PKEY* k = nullptr;
	Expect1(EVP_PKEY_keygen(kctx.get(), &k));
	mVal.reset(k);
}

Key::Key(RSA rsa)
{
	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> kctx{EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free};
	ExpectInitialized(kctx);
	Expect1(EVP_PKEY_keygen_init(kctx.get()));
	ExpectPos(EVP_PKEY_CTX_set_rsa_keygen_bits(kctx.get(), static_cast<int>(rsa)));
	EVP_PKEY* k = nullptr;
	Expect1(EVP_PKEY_keygen(kctx.get(), &k));
	mVal.reset(k);
}

Key::Key(Secret<> const& hmacKey)
{
	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> kctx{EVP_PKEY_CTX_new_id(EVP_PKEY_HMAC, nullptr), EVP_PKEY_CTX_free};
	ExpectInitialized(kctx);
	Expect1(EVP_PKEY_keygen_init(kctx.get()));
	ExpectPos(EVP_PKEY_CTX_ctrl(kctx.get(), -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_SET_MAC_KEY, hmacKey.size(), hmacKey.get()));
	EVP_PKEY* k = nullptr;
	Expect1(EVP_PKEY_keygen(kctx.get(), &k));
	mVal.reset(k);
}

Key::Key(Secret<> const& cmacKey, EVP_CIPHER const* cipher)
{
	std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> kctx{EVP_PKEY_CTX_new_id(EVP_PKEY_CMAC, nullptr), EVP_PKEY_CTX_free};
	ExpectInitialized(kctx);
	Expect1(EVP_PKEY_keygen_init(kctx.get()));
	ExpectPos(EVP_PKEY_CTX_ctrl(kctx.get(), -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_CIPHER, 0, (void*)cipher));
	ExpectPos(EVP_PKEY_CTX_ctrl(kctx.get(), -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_SET_MAC_KEY, cmacKey.size(), cmacKey.get()));
	EVP_PKEY* k = nullptr;
	Expect1(EVP_PKEY_keygen(kctx.get(), &k));
	mVal.reset(k);
}

Key::operator EVP_PKEY*() const noexcept
{ return mVal.get(); }

DerInfo::DerInfo(Input& input)
{
	try {
		input.read(tl, 2);
	} catch (Input::Exception const& exc) {
		tlLength = 2 - exc.getUnreadSize();
		throw;
	}
	if (tl[0] <= 0x31) { // single byte tag
		if (tl[1] <= 0x7F) {// single byte length
			tlLength = 2;
			vLength = tl[1];
		} else {
			unsigned char ll = tl[1] & 0x7F;
			if (ll > sizeof(long))
				throw Exception(std::make_error_code(static_cast<std::errc>(ERANGE)));

			vLength = 0;
			try {
				input.read(tl + 2, ll);
			} catch (Input::Exception const& exc) {
				tlLength = 2 + ll - exc.getUnreadSize();
				throw;
			}
			tlLength = 2 + ll;
			for (unsigned char i = 0; i < ll; ++i) // to little-endian
				*(reinterpret_cast<unsigned char*>(&vLength) + i) = tl[2 + ll - 1 - i];
		}
	} else
		throw Exception(std::make_error_code(static_cast<std::errc>(EINVAL)), "asn1 multibyte tag parsing is not implemented");
}

PrivateKey::PrivateKey(Key const& key)
		: mVal(EVP_PKEY2PKCS8(static_cast<EVP_PKEY*>(key)), PKCS8_PRIV_KEY_INFO_free)
{ ExpectInitialized(mVal); }

PrivateKey::PrivateKey(Input& input)
{
	Secret<DerInfo> i{input};
	Secret<> privKey(i->tlLength + i->vLength);
	std::memcpy(privKey.get(), i->tl, i->tlLength);
	input.read(privKey.get() + i->tlLength, i->vLength);

	auto const* in = privKey.get();
	mVal.reset(d2i_PKCS8_PRIV_KEY_INFO(nullptr, &in, static_cast<long>(privKey.size())));
	ExpectInitialized(mVal);
}

PrivateKey::operator PKCS8_PRIV_KEY_INFO*() const noexcept
{ return mVal.get(); }

Output&
operator<<(Output& output, PrivateKey const& privateKey)
{
	int length = i2d_PKCS8_PRIV_KEY_INFO(static_cast<PKCS8_PRIV_KEY_INFO*>(privateKey), nullptr);
	ExpectPos(length);
	Secret<> privKey(length);

	auto* p = privKey.get();
	length = i2d_PKCS8_PRIV_KEY_INFO(static_cast<PKCS8_PRIV_KEY_INFO*>(privateKey), &p);
	ExpectPos(length);
	return output.write(privKey.get(), length);
}

PublicKey::PublicKey(Key const& key)
{
	X509_PUBKEY* p = nullptr;
	Expect1(X509_PUBKEY_set(&p, static_cast<EVP_PKEY*>(key)));
	mVal.reset(p);
}

PublicKey::PublicKey(Input& input)
{
	DerInfo i(input);

	std::unique_ptr<unsigned char> pubKey(new unsigned char[i.tlLength + i.vLength]);
	std::memcpy(pubKey.get(), i.tl, i.tlLength);
	input.read(pubKey.get() + i.tlLength, i.vLength);

	auto const* in = pubKey.get();
	mVal.reset(d2i_X509_PUBKEY(nullptr, &in, i.tlLength + i.vLength));
	ExpectInitialized(mVal);
}

PublicKey::operator X509_PUBKEY*() const noexcept
{ return mVal.get(); }

Output&
operator<<(Output& output, PublicKey const& publicKey)
{
	int length = i2d_X509_PUBKEY(static_cast<X509_PUBKEY*>(publicKey), nullptr);
	ExpectPos(length);
	std::unique_ptr<unsigned char> pubKey(new unsigned char[length]);

	auto* p = pubKey.get();
	length = i2d_X509_PUBKEY(static_cast<X509_PUBKEY*>(publicKey), &p);
	ExpectPos(length);
	return output.write(pubKey.get(), length);
}

std::error_code
make_error_code(Key::Exception::Code e) noexcept
{
	static struct : std::error_category {
		[[nodiscard]] char const*
		name() const noexcept override
		{ return "Stream::Security::Key"; }

		[[nodiscard]] std::string
		message(int ev) const noexcept override
		{ return ERR_error_string(ev, nullptr); }
	} instance;
	return {static_cast<int>(e), instance};
}

}//namespace Stream::Security