#include <Security/Cipher.hpp>
#include <Stream/File.hpp>
#include <StreamTest/Util.hpp>
#include <openssl/rand.h>
#include <cassert>
#include <openssl/err.h>

#define Expect1(x) if (1 != x) throw std::runtime_error(ERR_error_string(ERR_peek_last_error(), nullptr))

void
writeNewSecretKey(std::string const& fileName, EVP_CIPHER const* cipher)
{
	Security::Secret<> secretKey{static_cast<std::size_t>(EVP_CIPHER_key_length(cipher))};
	Expect1(RAND_priv_bytes(secretKey.get(), secretKey.size()));
	Stream::File{fileName + ".sec", Stream::File::Mode::W}.write(secretKey.get(), secretKey.size());
}

Security::Secret<>
readSecretKey(std::string const& fileName)
{
	Stream::File file{fileName + ".sec", Stream::File::Mode::R};
	Security::Secret<> secretKey{static_cast<std::size_t>(file.getFileSize())};
	file.read(secretKey.get(), secretKey.size());
	return secretKey;
}

std::vector<std::byte>
testEncrypt(std::string const& fileName, EVP_CIPHER const* cipher, int length, int maxChunkLength)
{
	auto secretKey = readSecretKey(fileName);
	std::unique_ptr<std::byte[]> iv;
	std::vector<std::byte> toEncrypt = StreamTest::Util::GetRandomBytes<std::chrono::minutes>(length);

	Stream::File file{fileName, Stream::File::Mode::W};
	Stream::BufferOutput buffer{static_cast<std::size_t>(file.getBlockSize())};
	file < buffer;

	if (int ivLength = EVP_CIPHER_iv_length(cipher)) {
		iv.reset(new std::byte[ivLength]);
		RAND_bytes(reinterpret_cast<unsigned char*>(iv.get()), ivLength);
		buffer.write(iv.get(), ivLength);
	}

	Security::CipherEncrypt encryptor{cipher, secretKey, iv.get()};
	buffer < encryptor;

	StreamTest::Util::WriteRandomChunks(encryptor, toEncrypt,
			std::uniform_int_distribution<int> {1, maxChunkLength});
	return toEncrypt;
}

std::vector<std::byte>
testDecrypt(std::string const& fileName, EVP_CIPHER const* cipher, int length, int maxChunkLength)
{
	auto secretKey = readSecretKey(fileName);
	std::unique_ptr<std::byte[]> iv;
	std::vector<std::byte> decrypted;
	decrypted.resize(length);

	Stream::File file{fileName, Stream::File::Mode::R};
	Stream::BufferInput buffer{static_cast<std::size_t>(file.getBlockSize())};
	file > buffer;

	if (int ivLength = EVP_CIPHER_iv_length(cipher)) {
		iv.reset(new std::byte[ivLength]);
		buffer.read(iv.get(), ivLength);
	}

	Security::CipherDecrypt decryptor{cipher, secretKey, iv.get()};
	buffer > decryptor;

	StreamTest::Util::ReadRandomChunks(decryptor, decrypted,
			std::uniform_int_distribution<int> {1, maxChunkLength});
	return decrypted;
}

void
test(std::string const& fileName, EVP_CIPHER const* cipher, int length, int maxChunkLength)
{
	writeNewSecretKey(fileName, cipher);
	auto encrypt = testEncrypt(fileName, cipher, length, maxChunkLength);
	auto decrypt = testDecrypt(fileName, cipher, length, maxChunkLength);
	assert(encrypt == decrypt);
}

int main()
{
	std::random_device rd;
	std::mt19937 gen(rd());

	int length = 1024*64;
	int maxChunkLength = 256;

	length += std::uniform_int_distribution<int>{1, EVP_CIPHER_block_size(EVP_rc4()) > 1 ? EVP_CIPHER_block_size(EVP_rc4()) : EVP_MAX_BLOCK_LENGTH}(gen);
	test("rc4.enc", EVP_rc4(), length, maxChunkLength);

	length += std::uniform_int_distribution<int>{1, EVP_CIPHER_block_size(EVP_aes_256_cbc()) > 1 ? EVP_CIPHER_block_size(EVP_aes_256_cbc()) : EVP_MAX_BLOCK_LENGTH}(gen);
	test("cbc.enc", EVP_aes_256_cbc(), length, maxChunkLength);

	length += std::uniform_int_distribution<int>{1, EVP_CIPHER_block_size(EVP_aes_128_ctr()) > 1 ? EVP_CIPHER_block_size(EVP_aes_128_ctr()) : EVP_MAX_BLOCK_LENGTH}(gen);
	test("ctr.enc", EVP_aes_128_ctr(), length, maxChunkLength);

	length += std::uniform_int_distribution<int>{1, EVP_CIPHER_block_size(EVP_aes_128_ofb()) > 1 ? EVP_CIPHER_block_size(EVP_aes_128_ofb()) : EVP_MAX_BLOCK_LENGTH}(gen);
	test("ofb.enc", EVP_aes_128_ofb(), length, maxChunkLength);

	//	length += std::uniform_int_distribution<int>{1, EVP_CIPHER_block_size(EVP_aes_maxChunkLength_wrap()) > 1 ? EVP_CIPHER_block_size(EVP_aes_maxChunkLength_wrap()) : EVP_MAX_BLOCK_LENGTH}(gen);
	//test("wrap.enc", EVP_aes_maxChunkLength_wrap(), length, maxChunkLength);

	return 0;
}