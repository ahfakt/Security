#include <cassert>
#include <Stream/File.hpp>
#include <Stream/Buffer.hpp>
#include <StreamSecurity/Signature.hpp>
#include <Stream/Pipe.hpp>
#include <StreamTest/Util.hpp>

std::vector<std::byte>
testOutput(std::string const& fileName, EVP_MD const* md, Stream::Security::Key const& signKey, int length, int maxChunkLength)
{
	std::vector<std::byte> outputData = StreamTest::Util::GetRandomBytes<std::chrono::hours>(length);

	Stream::File file(fileName, Stream::File::Mode::W);
	Stream::BufferOutput buffer(file.getBlockSize());
	Stream::Security::SignatureOutput signatureOutput(md, signKey);
	file < buffer < signatureOutput;

	StreamTest::Util::WriteRandomChunks(signatureOutput, outputData,
			std::uniform_int_distribution<int> {1, maxChunkLength});

	return signatureOutput.getSignature();
}

void
testInput(std::string const& fileName, EVP_MD const* md, Stream::Security::Key const& verifyKey, std::vector<std::byte> const& signature, int length, int maxChunkLength)
{
	std::vector<std::byte> inputData;
	inputData.resize(length);

	Stream::File file(fileName, Stream::File::Mode::R);
	Stream::BufferInput buffer(file.getBlockSize());
	Stream::Security::SignatureInput signatureInput(md, verifyKey);
	file > buffer > signatureInput;

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
		Stream::File filePriv(fileName + ".priv.der", Stream::File::Mode::W);
		filePriv << privKey;
	}

	auto signature = testOutput(fileName, md, privKey, length, maxChunkLength);

	std::vector<std::byte> outputData = StreamTest::Util::GetRandomBytes<std::chrono::hours>(length);
	auto signature2 = Stream::Security::Signature::Sign(outputData.data(), outputData.size(), md, privKey);


	Stream::Security::PublicKey pubkey(key);
	{
		Stream::File filePub(fileName + "pub.der", Stream::File::Mode::W);
		filePub << pubkey;
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

	/*Due to the random seedings, this takes some time
	Stream::Pipe pipe;
	pipe
		<< Stream::Security::PrivateKey(Stream::Security::Key::EC::sect571r1)
		<< Stream::Security::PrivateKey(Stream::Security::Key::DSA::DSA15360)
		<< Stream::Security::PrivateKey(Stream::Security::Key::RSA::RSA15360);

	Stream::Security::PrivateKey ecPriv(pipe);
	Stream::Security::PrivateKey dsaPriv(pipe);
	Stream::Security::PrivateKey rsaPriv(pipe);
	*/

	test("sha256ec", EVP_sha256(), ecKey, length, maxChunkLength);
	test("sha256dsa", EVP_sha256(), dsaKey, length, maxChunkLength);
	test("sha256rsa", EVP_sha256(), rsaKey, length, maxChunkLength);

	return 0;
}
