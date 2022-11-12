#ifndef SECURITY_DIGEST_HPP
#define SECURITY_DIGEST_HPP

#include "Key.hpp"
#include <Stream/Transparent.hpp>
#include <vector>

namespace Security {

/**
 * @brief	Stream::Input %Digest observer
 * @class	DigestInput Digest.hpp "Security/Digest.hpp"
 */
class DigestInput : public Stream::TransparentInput {
	std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mCtx{nullptr, EVP_MD_CTX_free};

	std::size_t
	readBytes(std::byte* dest, std::size_t size) override;

protected:
	DigestInput(EVP_MD const* md, EVP_PKEY* key);

public:
	struct Exception : Stream::Input::Exception
	{ using Stream::Input::Exception::Exception; };

	explicit DigestInput(EVP_MD const* md);

	DigestInput(EVP_MD const* md, Key const& key);

	DigestInput(DigestInput&& other) noexcept;

	friend void
	swap(DigestInput& a, DigestInput& b) noexcept;

	DigestInput&
	operator=(DigestInput&& other) noexcept;

	[[nodiscard]] std::size_t
	getInputDigestSize() const noexcept;

	[[nodiscard]] std::vector<std::byte>
	getInputDigest() const;
};//class Security::DigestInput

/**
 * @brief	Stream::Output %Digest observer
 * @class	DigestOutput Digest.hpp "Security/Digest.hpp"
 */
class DigestOutput : public Stream::TransparentOutput {
	std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mCtx{nullptr, EVP_MD_CTX_free};

	std::size_t
	writeBytes(std::byte const* src, std::size_t size) override;

protected:
	DigestOutput(EVP_MD const* md, EVP_PKEY* key);

public:
	struct Exception : Stream::Output::Exception
	{ using Stream::Output::Exception::Exception; };

	explicit DigestOutput(EVP_MD const* md);

	DigestOutput(EVP_MD const* md, Key const& key);

	DigestOutput(DigestOutput&& other) noexcept;

	friend void
	swap(DigestOutput& a, DigestOutput& b) noexcept;

	DigestOutput&
	operator=(DigestOutput&& other) noexcept;

	[[nodiscard]] std::size_t
	getOutputDigestSize() const noexcept;

	[[nodiscard]] std::vector<std::byte>
	getOutputDigest() const;
};//class Security::DigestOutput

/**
 * @brief Stream::Input / Stream::Output %Digest observer
 * @class Digest Digest.hpp "Security/Digest.hpp"
 */
class Digest : public DigestInput, public DigestOutput {
	friend class DigestInput;
	friend class DigestOutput;

	static std::size_t
	Size(EVP_MD_CTX* ctx);

	static std::vector<std::byte>
	Value(EVP_MD_CTX* ctx);

public:
	static std::vector<std::byte>
	Compute(void const* data, std::size_t count, EVP_MD const* md);

	static std::vector<std::byte>
	Compute(void const* data, std::size_t count, EVP_MD const* md, Key const& key);

	static bool
	Matches(std::vector<std::byte> const& digest1, std::vector<std::byte> const& digest2) noexcept;

	struct Exception : std::system_error {
		using std::system_error::system_error;
		enum class Code : int {};
	};//struct Security::Digest::Exception

	explicit Digest(EVP_MD const* md);

	Digest(EVP_MD const* md, Key const& key);

	Digest(EVP_MD const* mdIn, EVP_MD const* mdOut);

	Digest(EVP_MD const* mdIn, EVP_MD const* mdOut, Key const& outKey);

	Digest(EVP_MD const* mdIn, Key const& inKey, EVP_MD const* mdOut);

	Digest(EVP_MD const* mdIn, Key const& inKey, EVP_MD const* mdOut, Key const& outKey);
};//class Security::Digest

void
swap(Digest& a, Digest& b) noexcept;

std::error_code
make_error_code(Digest::Exception::Code e) noexcept;

}//namespace Security

namespace std {

template <>
struct is_error_code_enum<Security::Digest::Exception::Code> : true_type {};

}//namespace std

#endif //SECURITY_DIGEST_HPP
