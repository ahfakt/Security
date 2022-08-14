#include <Stream/Socket.hpp>
#include <StreamSecurity/TLS.hpp>
#include <cstring>
#include <iostream>
#include <Stream/File.hpp>
#include <thread>

#define MAX_HTTP_BUFFER_SIZE 64*1024

void
testTLSClient()
{
	auto ctx = Stream::Security::TLS::Context(TLS_client_method());

	Stream::Socket server(Stream::Socket::Inet("api.binance.com", 443));
	Stream::Buffer buffer(server.getMSS());
	Stream::Security::TLS tls(ctx);
	server <=> buffer <=> tls;

	std::string request(
		"GET /api/v3/ticker/price?symbol=ETHUSDT HTTP/1.1\r\n"
		"Host: api.binance.com\r\n"
		"Accept-Encoding: text/json\r\n"
		"Connection: close\r\n\r\n"
	);

	tls.write(request.data(), request.size());
	std::string response;
	response.resize(MAX_HTTP_BUFFER_SIZE);
	response.resize(tls.readSome(response.data(), response.size()));
	std::cout << response.data() << std::endl;
}

Stream::Security::Certificate
GetCertificate(char const* fileName)
{
	Stream::File certFile(fileName, Stream::File::Mode::R);
	Stream::BufferInput bufferInput(certFile.getFileSize());
	certFile > bufferInput;
	return Stream::Security::Certificate{bufferInput};
}

Stream::Security::PrivateKey
GetPrivateKey(char const* fileName)
{
	Stream::File file(fileName, Stream::File::Mode::R);

	Stream::Security::Secret<> secret(file.getFileSize());
	file.read(secret.get(), secret.size());

	Stream::BufferInput bufferInput(secret.get(), secret.size());
	return Stream::Security::PrivateKey{bufferInput};
}

void
testTLSServer()
{
	auto ctx = Stream::Security::TLS::Context(TLS_server_method(),
			GetCertificate("server.crt.der"),
			GetPrivateKey("server.key.der"));
	//SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);

	Stream::Socket server(Stream::Socket::Inet("application.loc", 8443), 4096);

	for (int i = 0, m = 1000000; i < m; ++i)
		std::thread([](Stream::Socket client, Stream::Security::TLS::Context const& ctx, int clientNumber) {
			std::string response(
				"HTTP/1.1 200 OK\r\n"
				"Content-Length: 140\r\n"
				"Content-Type: text/html\r\n"
				"Connection: close\r\n\r\n"
				"<html>"
					"<head>"
						"<link rel=\"icon\" href=\"data:;base64,iVBORw0KGgo=\">"
					"</head>"
					"<body>"
						"<h1>Hello, World!</h1>"
						"<p>Request Number: ......</p>"
					"</body>"
				"</html>"
			);

			try {
				Stream::Buffer buffer(client.getMSS());
				Stream::Security::TLS tls(ctx);
				client <=> buffer <=> tls;

				std::string request;
				request.resize(MAX_HTTP_BUFFER_SIZE);
				request.resize(tls.readSome(request.data(), request.size()));
				std::cout << request << std::endl;

				std::string c = std::to_string(clientNumber);
				c.insert(c.begin(), 6 - c.size(), ' ');
				std::memcpy(response.data() + 200, c.data(), 6);

				tls.write(response.data(), response.size());
				tls.shutdown();

				//if (std::string::npos != request.find("Connection: close"))
				//	break;

			} catch (std::system_error& exc) {
				std::cerr << exc.code().category().name() << " : " << exc.code().message() << std::endl;
			}
		}, server.accept(), std::cref(ctx), i).detach();
}

int main() {
	testTLSClient();
	testTLSServer();
	return 0;
}

/**

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256
openssl genpkey -aes256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private-key.pem


echo 'Generating private key: rootCA.key.pem' && \
openssl ecparam \
		-name prime256v1 -genkey \
		-out rootCA.key.pem && \
echo 'Check private key: rootCA.key.pem' && \
openssl ec \
		-in rootCA.key.pem \
		-check -noout && \
echo 'Convert private key to DER PKCS8 format: rootCA.key.der' && \
openssl pkcs8 \
		-topk8 -nocrypt \
		-in rootCA.key.pem \
		-out rootCA.key.der -outform der && \
echo 'Extract public key from private key: rootCA.pub.pem' && \
openssl pkey \
		-in rootCA.key.pem -pubout \
		-out rootCA.pub.pem && \
echo 'Generate self-signed certificate with private key and temporary certificate signing request: rootCA.crt.der' && \
openssl req -sha256 \
		-key rootCA.key.pem \
		-new -x509 -days 3650 \
		-subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=Authority" \
		-addext "subjectAltName=DNS:authority.loc,DNS:*.authority.loc" \
		-out rootCA.crt.der -outform der && \
echo 'View certificate: rootCA.crt.der' && \
openssl x509 \
		-in rootCA.crt.der -inform der \
		-text -noout && \
echo 'Convert certificate to PEM certificate: rootCA.crt.pem' && \
openssl x509 \
		-in rootCA.crt.der -inform der \
		-out rootCA.crt.pem -outform pem && \
echo 'Add authority to system (requires root permission): rootCA.crt.pem' && \
sudo cp -r rootCA.crt.pem /etc/ssl/certs


echo 'Generating private key: server.key.pem' && \
openssl ecparam \
		-name prime256v1 -genkey \
		-out server.key.pem && \
echo 'Check private key: server.key.pem' && \
openssl ec \
		-in server.key.pem \
		-check -noout && \
echo 'Convert private key to DER PKCS8 format: server.key.der' && \
openssl pkcs8 \
		-topk8 -nocrypt \
		-in server.key.pem \
		-out server.key.der -outform der && \
echo 'Extract public key from private key: server.pub.pem' && \
openssl pkey \
		-in server.key.pem -pubout \
		-out server.pub.pem && \
echo 'Generate certificate signing request with private key: server.csr.pem' && \
openssl req -sha256 \
		-key server.key.pem \
		-subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=Application" \
		-addext "subjectAltName=DNS:application.loc,DNS:*.application.loc" \
		-new -out server.csr.pem && \
echo 'Verify certificate signing request: server.csr.pem' && \
openssl req \
		-text -noout -verify \
		-in server.csr.pem && \
echo 'Sign with an authority: server.crt.der' && \
openssl x509 \
		-req -extfile <(printf "subjectAltName=DNS:application.loc,DNS:*.application.loc") -days 365 -sha256 \
		-in server.csr.pem \
		-CA rootCA.crt.pem -CAkey rootCA.key.pem -CAcreateserial \
		-out server.crt.der -outform der && \
echo 'View certificate: server.crt.der' && \
openssl x509 \
		-in server.crt.der -inform der \
		-text -noout


echo 'Generate certificate signing request with existing certificate and private key: server.csr.pem' && \
openssl x509 \
		-in server.crt.der -inform der \
		-signkey server.key.der -keyform der \
		-x509toreq -out server.csr.pem && \
echo 'Verify certificate signing request: server.csr.pem' && \
openssl req \
		-text -noout -verify \
		-in server.csr.pem && \
echo 'Sign with an authority: server.crt.der' && \
openssl x509 \
		-req -extfile <(printf "subjectAltName=DNS:application.loc,DNS:*.application.loc") -days 365 -sha256 \
		-in server.csr.pem \
		-CA rootCA.crt.pem -CAkey rootCA.key.pem -CAcreateserial \
		-out server.crt.der -outform der && \
echo 'View certificate: server.crt.der' && \
openssl x509 \
		-in server.crt.der -inform der \
		-text -noout && \
echo 'Add domain name to /etc/hosts (requires root permission)' && \
sudo echo '127.0.0.1 application.loc' >> /etc/hosts

*/

