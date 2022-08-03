#include <cassert>
#include <Stream/File.hpp>
#include <Stream/Buffer.hpp>
#include <StreamSecurity/Digest.hpp>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "Util.hpp"

#define Expect1(x) if (1 != x) throw std::runtime_error(ERR_error_string(ERR_peek_last_error(), nullptr))

std::vector<std::byte>
testOutputHash(std::string const& fileName, EVP_MD const* md, int length, int maxChunkLength)
{
	std::vector<std::byte> outputData = StreamTest::Util::GetRandomBytes<std::chrono::minutes>(length);

	IO::File io(fileName, IO::File::Mode::W);
	Stream::FileOutput file;
	Stream::BufferOutput buffer(io.getBlockSize());
	Stream::Security::DigestOutput digestOutput(md);
	io << file << buffer << digestOutput;

	StreamTest::Util::WriteRandomChunks(digestOutput, outputData,
			std::uniform_int_distribution<int> {1, maxChunkLength});

	auto outputDigest = digestOutput.getOutputDigest();
	assert(Stream::Security::Digest::Matches(outputDigest,
			Stream::Security::Digest::Compute(outputData.data(), outputData.size(), md)));
	return outputDigest;
}

std::vector<std::byte>
testOutputHMAC(std::string const& fileName, EVP_MD const* md, Stream::Security::Key const& key, int length, int maxChunkLength)
{
	std::vector<std::byte> outputData = StreamTest::Util::GetRandomBytes<std::chrono::minutes>(length);

	IO::File io(fileName, IO::File::Mode::W);
	Stream::FileOutput file;
	Stream::BufferOutput buffer(io.getBlockSize());
	Stream::Security::DigestOutput digestOutput(md, key);
	io << file << buffer << digestOutput;

	StreamTest::Util::WriteRandomChunks(digestOutput, outputData,
			std::uniform_int_distribution<int> {1, maxChunkLength});

	auto outputDigest = digestOutput.getOutputDigest();
	assert(Stream::Security::Digest::Matches(outputDigest,
			Stream::Security::Digest::Compute(outputData.data(), outputData.size(), md, key)));
	return outputDigest;
}

std::vector<std::byte>
testInputHash(std::string const& fileName, EVP_MD const* md, int length, int maxChunkLength)
{
	std::vector<std::byte> inputData;
	inputData.resize(length);

	IO::File io(fileName, IO::File::Mode::R);
	Stream::FileInput file;
	Stream::BufferInput buffer(io.getBlockSize());
	Stream::Security::DigestInput digestInput(md);
	io >> file >> buffer >> digestInput;

	StreamTest::Util::ReadRandomChunks(digestInput, inputData,
			std::uniform_int_distribution<int> {1, maxChunkLength});

	auto inputDigest = digestInput.getInputDigest();
	assert(Stream::Security::Digest::Matches(inputDigest,
			Stream::Security::Digest::Compute(inputData.data(), inputData.size(), md)));
	return inputDigest;
}

std::vector<std::byte>
testInputHMAC(std::string const& fileName, EVP_MD const* md, Stream::Security::Key const& key, int length, int maxChunkLength)
{
	std::vector<std::byte> inputData;
	inputData.resize(length);

	IO::File io(fileName, IO::File::Mode::R);
	Stream::FileInput file;
	Stream::BufferInput buffer(io.getBlockSize());
	Stream::Security::DigestInput digestInput(md, key);
	io >> file >> buffer >> digestInput;

	StreamTest::Util::ReadRandomChunks(digestInput, inputData,
			std::uniform_int_distribution<int> {1, maxChunkLength});

	auto inputDigest = digestInput.getInputDigest();
	assert(Stream::Security::Digest::Matches(inputDigest,
			Stream::Security::Digest::Compute(inputData.data(), inputData.size(), md, key)));
	return inputDigest;
}

void
testHash(std::string const& fileName, EVP_MD const* md, int length, int maxChunkLength)
{
	auto outputDigest = testOutputHash(fileName, md,  length, maxChunkLength);
	auto inputDigest = testInputHash(fileName, md, length, maxChunkLength);
	assert(Stream::Security::Digest::Matches(outputDigest, inputDigest));
}

void
testHMAC(std::string const& fileName, EVP_MD const* md, Stream::Security::Key const& key, int length, int maxChunkLength)
{
	auto outputHMAC = testOutputHMAC(fileName, md, key,  length, maxChunkLength);
	auto inputHMAC = testInputHMAC(fileName, md, key, length, maxChunkLength);
	assert(Stream::Security::Digest::Matches(outputHMAC, inputHMAC));
}

void
testCMAC(std::string const& fileName, Stream::Security::Key const& key, int length, int maxChunkLength)
{
	auto outputCMAC = testOutputHMAC(fileName, nullptr, key,  length, maxChunkLength);
	auto inputCMAC = testInputHMAC(fileName, nullptr, key, length, maxChunkLength);
	assert(Stream::Security::Digest::Matches(outputCMAC, inputCMAC));
}

int main() {
	std::random_device rd;
	std::mt19937 gen(rd());

	int length = 1024*64;
	int maxChunkLength = 256;

	length += std::uniform_int_distribution<int>{1, 5}(gen);
	testHash("sha256.hash", EVP_sha256(), length, maxChunkLength);

	int hKeyLength = EVP_MD_size(EVP_sha256());
	Stream::Security::SecureMemory hKeyRaw(new unsigned char[hKeyLength], hKeyLength);
	Expect1(RAND_priv_bytes(hKeyRaw.get(), hKeyLength));
	Stream::Security::Key const hkey(hKeyRaw);
	testHMAC("sha256.hmac", EVP_sha256(), hkey, length, maxChunkLength);

	int cKeyLength = EVP_CIPHER_key_length(EVP_aes_256_cbc());
	Stream::Security::SecureMemory cKeyRaw(new unsigned char[cKeyLength], cKeyLength);
	Expect1(RAND_priv_bytes(hKeyRaw.get(), cKeyLength));
	Stream::Security::Key const ckey(cKeyRaw, EVP_aes_256_cbc());
	testCMAC("sha256.cmac", ckey, length, maxChunkLength);

	return 0;
}

