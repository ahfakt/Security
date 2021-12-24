#ifndef STREAM_SECURITY_SIGNATURE_H
#define STREAM_SECURITY_SIGNATURE_H

#include "Stream/InOut.h"
#include "Key.h"
#include <vector>

namespace Stream::Security {

/**
 * @brief	Input stream signature observer
 * @class	SignatureInput Signature.h "StreamSecurity/Signature.h"
 */
class SignatureInput : public InputFilter {
	std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mCtx{nullptr, EVP_MD_CTX_free};

	std::size_t
	readBytes(std::byte* dest, std::size_t size) override;

public:
	struct Exception : Input::Exception
	{ using Input::Exception::Exception; };

	SignatureInput(EVP_MD const* md, Key const& verifyKey);

	SignatureInput(SignatureInput&& other) noexcept;

	friend void
	swap(SignatureInput& a, SignatureInput& b) noexcept;

	SignatureInput&
	operator=(SignatureInput&& other) noexcept;

	[[nodiscard]] bool
	verifySignature(std::vector<std::byte> const& signature) const;
};//class SignatureInput

/**
 * @brief	Output stream signature observer
 * @class	SignatureOutput Signature.h "StreamSecurity/Signature.h"
 */
class SignatureOutput : public OutputFilter {
	std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mCtx{nullptr, EVP_MD_CTX_free};

	std::size_t
	writeBytes(std::byte const* src, std::size_t size) override;

public:
	struct Exception : Output::Exception
	{ using Output::Exception::Exception; };

	SignatureOutput(EVP_MD const* md, Key const& signKey);

	SignatureOutput(SignatureOutput&& other) noexcept;

	friend void
	swap(SignatureOutput& a, SignatureOutput& b) noexcept;

	SignatureOutput&
	operator=(SignatureOutput&& other) noexcept;

	[[nodiscard]] std::size_t
	getSignatureSize() const;

	[[nodiscard]] std::vector<std::byte>
	getSignature() const;
};//class SignatureOutput

/**
 * @brief Input / Output stream signature observer
 * @class Signature Signature.h "StreamSecurity/Signature.h"
 */
class Signature : public SignatureInput, public SignatureOutput {
	friend class SignatureInput;
	friend class SignatureOutput;

	static std::size_t
	Size(EVP_MD_CTX* ctx);

	static std::vector<std::byte>
	Sign(EVP_MD_CTX* ctx);

	static bool
	Verify(EVP_MD_CTX* ctx, std::vector<std::byte> const& signature);
public:
	static std::vector<std::byte>
	Sign(void const* data, std::size_t count, EVP_MD const* md, Key const& signKey);

	static bool
	Verify(void const* data, std::size_t count, EVP_MD const* md, Key const& verifyKey, std::vector<std::byte> const& signature);

	struct Exception : std::system_error {
		using std::system_error::system_error;
		enum class Code : int {};
	};//struct Exception

	Signature(EVP_MD const* mdIn, Key const& verifyKey, EVP_MD const* mdOut, Key const& signKey);

	Signature(EVP_MD const* md, Key const& key);
};
//class Signature

std::error_code
make_error_code(Signature::Exception::Code e) noexcept;

}//namespace Stream::Security

namespace std {

template <>
struct is_error_code_enum<Stream::Security::Signature::Exception::Code> : true_type {};

}//namespace std

#endif //STREAM_SECURITY_SIGNATURE_H
