#include <cassert>
#include <Stream/File.h>
#include <Stream/Buffer.h>
#include <StreamSecurity/Signature.h>
#include <IO/Pipe.h>
#include <Stream/Pipe.h>
#include "Util.h"

std::vector<std::byte>
testOutput(std::string const& fileName, EVP_MD const* md, Stream::Security::Key const& signKey, int length, int maxChunkLength)
{
	std::vector<std::byte> outputData = StreamTest::Util::GetRandomBytes<std::chrono::hours>(length);

	IO::File io(fileName, IO::File::Mode::W);
	Stream::FileOutput file;
	Stream::BufferOutput buffer(io.getBlockSize());
	Stream::Security::SignatureOutput signatureOutput(md, signKey);
	io << file << buffer << signatureOutput;

	StreamTest::Util::WriteRandomChunks(signatureOutput, outputData,
			std::uniform_int_distribution<int> {1, maxChunkLength});

	return signatureOutput.getSignature();
}

void
testInput(std::string const& fileName, EVP_MD const* md, Stream::Security::Key const& verifyKey, std::vector<std::byte> const& signature, int length, int maxChunkLength)
{
	std::vector<std::byte> inputData;
	inputData.resize(length);

	IO::File io(fileName, IO::File::Mode::R);
	Stream::FileInput file;
	Stream::BufferInput buffer(io.getBlockSize());
	Stream::Security::SignatureInput signatureInput(md, verifyKey);
	io >> file >> buffer >> signatureInput;

	StreamTest::Util::ReadRandomChunks(signatureInput, inputData,
			std::uniform_int_distribution<int> {1, maxChunkLength});

	assert(signatureInput.verifySignature(signature));
	assert(Stream::Security::Signature::Verify(inputData.data(), inputData.size(), md, verifyKey, signature));
}

void
test(std::string const& fileName, EVP_MD const* md, Stream::Security::Key const& key, int length, int maxChunkLength)
{
	Stream::Security::PrivateKey privKey(key);
	{
		IO::File ioPriv(fileName + ".priv.der", IO::File::Mode::W);
		Stream::FileOutput filePriv;
		ioPriv << filePriv << privKey;
	}

	auto signature = testOutput(fileName, md, privKey,  length, maxChunkLength);

	std::vector<std::byte> outputData = StreamTest::Util::GetRandomBytes<std::chrono::hours>(length);
	auto signature2 = Stream::Security::Signature::Sign(outputData.data(), outputData.size(), md, privKey);


	Stream::Security::PublicKey pubkey(key);
	{
		IO::File ioPub(fileName + "pub.der", IO::File::Mode::W);
		Stream::FileOutput filePub;
		ioPub << filePub << pubkey;
	}

	testInput(fileName, md, pubkey, signature, length, maxChunkLength);
	testInput(fileName, md, pubkey, signature2, length, maxChunkLength);
}

int main() {
	std::random_device rd;
	std::mt19937 gen(rd());

	int length = 1024*64;
	int maxChunkLength = 256;

	length += std::uniform_int_distribution<int>{1, 5}(gen);
	Stream::Security::Key ecKey(Stream::Security::Key::EC::prime256v1);
	Stream::Security::Key dsaKey(Stream::Security::Key::DSA::DSA3072);
	Stream::Security::Key rsaKey(Stream::Security::Key::RSA::RSA3072);

	IO::Pipe io;
	Stream::Pipe pipeStream;
	io <=> pipeStream;

	pipeStream
		<< Stream::Security::PrivateKey(Stream::Security::Key::EC::sect571r1)
		<< Stream::Security::PrivateKey(Stream::Security::Key::DSA::DSA15360)
		<< Stream::Security::PrivateKey(Stream::Security::Key::RSA::RSA15360);

	Stream::Security::PrivateKey ecPriv(pipeStream);
	Stream::Security::PrivateKey dsaPriv(pipeStream);
	Stream::Security::PrivateKey rsaPriv(pipeStream);

	test("sha256ec", EVP_sha256(), ecKey, length, maxChunkLength);
	test("sha256dsa", EVP_sha256(), dsaKey, length, maxChunkLength);
	test("sha256rsa", EVP_sha256(), rsaKey, length, maxChunkLength);

	return 0;
}

