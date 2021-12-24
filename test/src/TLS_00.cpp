#include <Stream/Socket.h>
#include <StreamSecurity/TLS.h>
#include <cstring>
#include <iostream>
#include <Stream/File.h>
#include <thread>
#include "Util.h"

#define MAX_HTTP_BUFFER_SIZE 64*1024

Stream::Security::Certificate
GetCertificateFromFile(std::string const& certFileName)
{
	IO::File io(certFileName, IO::File::Mode::R);
	Stream::FileInput certFile;
	io >> certFile;
	return Stream::Security::Certificate(certFile);
}

Stream::Security::PrivateKey
GetPrivateKeyFromFile(std::string const& keyFileName)
{
	IO::File io(keyFileName, IO::File::Mode::R);
	Stream::FileInput privKeyFile;
	io >> privKeyFile;
	return Stream::Security::PrivateKey(privKeyFile);
}

void
HandleClient(IO::Socket io, Stream::Security::TLS::Context const& ctx, int clientNumber)
{
	std::string response(
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 139\r\n"
		"Content-Type: text/html\r\n"
		"Connection: close\r\n\r\n"
		"<html>"
			"<head>"
				"<link rel=\"icon\" href=\"data:;base64,iVBORw0KGgo=\">"
			"</head>"
			"<body>"
				"<h1>Hello, World!</h1>"
				"<p>Client Number: ......</p>"
			"</body>"
		"</html>"
	);

	try {
		Stream::Socket socket;
		Stream::Security::TLS tls(ctx);
		io <=> socket <=> tls;

		std::string request;
		request.resize(MAX_HTTP_BUFFER_SIZE);
		request.resize(tls.readSome(request.data(), request.size()));
		std::cout << request << std::endl;

		std::string c = std::to_string(clientNumber);
		c.insert(c.begin(), 6 - c.size(), ' ');
		std::memcpy(response.data() + 199, c.data(), 6);

		tls.write(response.data(), response.size());
		tls.shutdown();

		//if (std::string::npos != request.find("Connection: close"))
		//	break;

	} catch (std::system_error& exc) {
		std::cerr << exc.code().category().name() << " : " << exc.code().message() << std::endl;
	}
}

void
testTLSServer()
{
	auto ctx = Stream::Security::TLS::Context(TLS_server_method(),
			GetCertificateFromFile("server.crt.der"),
			GetPrivateKeyFromFile("server.key.der"));
	//SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);

	IO::Socket server(IO::Socket::INET("127.0.0.1", 8443), 4096);

	for (int i = 0, m = 1000000; i < m; ++i) {
		auto client = server.accept();
		std::thread(HandleClient, std::move(client), std::cref(ctx), i).detach();
	}
}

void
testTLSClient()
{
	auto ctx = Stream::Security::TLS::Context(TLS_client_method());

	IO::Socket io(IO::Socket::INET("13.224.63.124", 443));
	Stream::Socket socket;
	Stream::Security::TLS tls(ctx);
	io <=> socket <=> tls;

	std::string request(
		"GET /api/v3/ticker/price?symbol=BTCUSDT HTTP/1.1\r\n"
		"Host: api.binance.com\r\n"
		"Accept-Encoding: text/json\r\n"
		"Connection: close\r\n\r\n"
	);

	tls.write(request.data(), request.size());
	std::string response;
	response.resize(MAX_HTTP_BUFFER_SIZE);
	response.resize(tls.readSome(response.data(), response.size()));
	std::cout << response << std::endl;
}

int main() {
	testTLSClient();
	testTLSServer();
	return 0;
}

/**

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256
openssl genpkey -aes256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private-key.pem

# Generate PEM Private Key
# Check PEM Private Key
# Convert PEM Private Key to DER PKCS8 Format
# Extract PEM Public Key from PEM Private Key
# Generate DER Self-Signed Certificate with PEM Private Key and Temporary Certificate Signing Request
# View DER Certificate
# Convert DER Certificate to PEM Certificate
openssl ecparam \
		-name prime256v1 -genkey \
		-out rootCA.key.pem && \
openssl ec \
		-in rootCA.key.pem \
		-check -noout && \
openssl pkcs8 \
		-topk8 -nocrypt \
		-in rootCA.key.pem \
		-out rootCA.key.der -outform der && \
openssl pkey \
		-in rootCA.key.pem -pubout \
		-out rootCA.pub.pem && \
openssl req -sha256 \
		-key rootCA.key.pem \
		-new -x509 -days 3650 \
		-subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=Authority" \
		-addext "subjectAltName=DNS:domain.loc,DNS:*.domain.loc" \
		-out rootCA.crt.der -outform der && \
openssl x509 \
		-in rootCA.crt.der -inform der \
		-text -noout && \
openssl x509 \
		-in rootCA.crt.der -inform der \
		-out rootCA.crt.pem -outform pem && \
sudo cp -r rootCA.crt.pem /etc/ssl/certs



# Generate PEM Private Key
# Check PEM Private Key
# Convert PEM Private Key to DER PKCS8 Format
# Extract PEM Public Key from PEM Private Key
# Generate PEM Certificate Signing Request with PEM Private Key
# Verify PEM Certificate Signing Request
# Sign
# View DER Certificate
openssl ecparam \
		-name prime256v1 -genkey \
		-out server.key.pem && \
openssl ec \
		-in server.key.pem \
		-check -noout && \
openssl pkcs8 \
		-topk8 -nocrypt \
		-in server.key.pem \
		-out server.key.der -outform der && \
openssl pkey \
		-in server.key.pem -pubout \
		-out server.pub.pem && \
openssl req -sha256 \
		-key server.key.pem \
		-subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=Application" \
		-addext "subjectAltName=DNS:domain.loc,DNS:*.domain.loc" \
		-new -out server.csr.pem && \
openssl req \
		-text -noout -verify \
		-in server.csr.pem && \
openssl x509 \
		-req -extfile <(printf "subjectAltName=DNS:domain.loc,DNS:*.domain.loc") -days 365 -sha256 \
		-in server.csr.pem \
		-CA rootCA.crt.pem -CAkey rootCA.key.pem -CAcreateserial \
		-out server.crt.der -outform der && \
openssl x509 \
		-in server.crt.der -inform der \
		-text -noout

# Generate PEM Certificate Signing Request with Existing DER Certificate and DER Private Key
#
openssl x509 \
		-in server.crt.der -inform der \
		-signkey server.key.der -keyform der \
		-x509toreq -out server.csr.pem && \
openssl x509 \
		-signkey rootCA.key.der -keyform der \
		-in server.csr.pem \
		-req -extfile <(printf "subjectAltName=DNS:domain.loc,DNS:*.domain.loc") -days 365 -sha256 \
		-out server.crt.der -outform der && \


*/

