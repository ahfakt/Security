#include <Stream/File.hpp>
#include <Stream/Buffer.hpp>
#include <Security/Digest.hpp>
#include <cassert>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <StreamTest/Util.hpp>

#define Expect1(x) if (1 != x) throw std::runtime_error(ERR_error_string(ERR_peek_last_error(), nullptr))

std::vector<std::byte>
testOutputHash(std::string const& fileName, EVP_MD const* md, int length, int maxChunkLength)
{
	std::vector<std::byte> outputData = StreamTest::GetRandomBytes<std::chrono::minutes>(length);

	Stream::File file(fileName, Stream::File::Mode::W);
	Stream::BufferOutput buffer(file.getBlockSize());
	Security::DigestOutput digestOutput(md);
	file < buffer < digestOutput;

	StreamTest::WriteRandomChunks(digestOutput, outputData,
			std::uniform_int_distribution<int> {1, maxChunkLength});

	auto outputDigest = digestOutput.getOutputDigest();
	assert(Security::Digest::Matches(outputDigest,
			Security::Digest::Compute(outputData.data(), outputData.size(), md)));
	return outputDigest;
}

std::vector<std::byte>
testOutputHMAC(std::string const& fileName, EVP_MD const* md, Security::Key const& key, int length, int maxChunkLength)
{
	std::vector<std::byte> outputData = StreamTest::GetRandomBytes<std::chrono::minutes>(length);

	Stream::File file(fileName, Stream::File::Mode::W);
	Stream::BufferOutput buffer(file.getBlockSize());
	Security::DigestOutput digestOutput(md, key);
	file < buffer < digestOutput;

	StreamTest::WriteRandomChunks(digestOutput, outputData,
			std::uniform_int_distribution<int> {1, maxChunkLength});

	auto outputDigest = digestOutput.getOutputDigest();
	assert(Security::Digest::Matches(outputDigest,
			Security::Digest::Compute(outputData.data(), outputData.size(), md, key)));
	return outputDigest;
}

std::vector<std::byte>
testInputHash(std::string const& fileName, EVP_MD const* md, int length, int maxChunkLength)
{
	std::vector<std::byte> inputData;
	inputData.resize(length);

	Stream::File file(fileName, Stream::File::Mode::R);
	Stream::BufferInput buffer(file.getBlockSize());
	Security::DigestInput digestInput(md);
	file > buffer > digestInput;

	StreamTest::ReadRandomChunks(digestInput, inputData,
			std::uniform_int_distribution<int> {1, maxChunkLength});

	auto inputDigest = digestInput.getInputDigest();
	assert(Security::Digest::Matches(inputDigest,
			Security::Digest::Compute(inputData.data(), inputData.size(), md)));
	return inputDigest;
}

std::vector<std::byte>
testInputHMAC(std::string const& fileName, EVP_MD const* md, Security::Key const& key, int length, int maxChunkLength)
{
	std::vector<std::byte> inputData;
	inputData.resize(length);

	Stream::File file(fileName, Stream::File::Mode::R);
	Stream::BufferInput buffer(file.getBlockSize());
	Security::DigestInput digestInput(md, key);
	file > buffer > digestInput;

	StreamTest::ReadRandomChunks(digestInput, inputData,
			std::uniform_int_distribution<int> {1, maxChunkLength});

	auto inputDigest = digestInput.getInputDigest();
	assert(Security::Digest::Matches(inputDigest,
			Security::Digest::Compute(inputData.data(), inputData.size(), md, key)));
	return inputDigest;
}

void
testHash(std::string const& fileName, EVP_MD const* md, int length, int maxChunkLength)
{
	auto outputDigest = testOutputHash(fileName, md,  length, maxChunkLength);
	auto inputDigest = testInputHash(fileName, md, length, maxChunkLength);
	assert(Security::Digest::Matches(outputDigest, inputDigest));
}

void
testHMAC(std::string const& fileName, EVP_MD const* md, Security::Key const& key, int length, int maxChunkLength)
{
	auto outputHMAC = testOutputHMAC(fileName, md, key,  length, maxChunkLength);
	auto inputHMAC = testInputHMAC(fileName, md, key, length, maxChunkLength);
	assert(Security::Digest::Matches(outputHMAC, inputHMAC));
}

void
testCMAC(std::string const& fileName, Security::Key const& key, int length, int maxChunkLength)
{
	auto outputCMAC = testOutputHMAC(fileName, nullptr, key,  length, maxChunkLength);
	auto inputCMAC = testInputHMAC(fileName, nullptr, key, length, maxChunkLength);
	assert(Security::Digest::Matches(outputCMAC, inputCMAC));
}

int main() {
	std::random_device rd;
	std::mt19937 gen(rd());

	int length = 1024*64;
	int maxChunkLength = 256;

	length += std::uniform_int_distribution<int>{1, 5}(gen);
	testHash("sha256.hash", EVP_sha256(), length, maxChunkLength);

	Security::Secret<> hKeyRaw(EVP_MD_size(EVP_sha256()));
	Expect1(RAND_priv_bytes(hKeyRaw.get(), hKeyRaw.size()));
	Security::Key const hkey(hKeyRaw);
	testHMAC("sha256.hmac", EVP_sha256(), hkey, length, maxChunkLength);

	Security::Secret<> cKeyRaw(EVP_CIPHER_key_length(EVP_aes_256_cbc()));
	Expect1(RAND_priv_bytes(cKeyRaw.get(), cKeyRaw.size()));
	Security::Key const ckey(cKeyRaw, EVP_aes_256_cbc());
	testCMAC("sha256.cmac", ckey, length, maxChunkLength);

	return 0;
}

