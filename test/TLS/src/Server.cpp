#include <Stream/Socket.hpp>
#include <StreamSecurity/TLS.hpp>
#include <cstring>
#include <iostream>
#include <Stream/File.hpp>
#include <thread>

/**
 * First create a CA with "script/rootCA" or "script/ca"
 * Then create app key, csr and crt by executing "script/app"
 */

#define MAX_HTTP_BUFFER_SIZE 64*1024

Stream::Security::Certificate
GetCertificate(char const* fileName)
{
	Stream::File certFile{fileName, Stream::File::Mode::R};
	Stream::BufferInput bufferInput{static_cast<std::size_t>(certFile.getFileSize())};
	certFile > bufferInput;
	return Stream::Security::Certificate{bufferInput};
}

Stream::Security::PrivateKey
GetPrivateKey(char const* fileName)
{
	Stream::File keyFile{fileName, Stream::File::Mode::R};

	Stream::Security::Secret<> secret{static_cast<std::size_t>(keyFile.getFileSize())};
	keyFile.read(secret.get(), secret.size());

	Stream::BufferInput bufferInput{secret.get(), secret.size()};
	return Stream::Security::PrivateKey{bufferInput};
}


int main() {
	auto ctx = Stream::Security::TLS::Context{TLS_server_method(),
			GetCertificate("app.local.crt.der"),
			GetPrivateKey("app.local.key.der")};
	//SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);

	Stream::Socket server{Stream::Socket::Address::Inet{"app.local", 8443}, 4096};

	for (int i = 0, m = 1000000; i < m; ++i) {
		std::thread([](Stream::Socket client, Stream::Security::TLS::Context const& ctx, int reqNumber) {
			std::string response{
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
			};

			try {
				Stream::Buffer buffer{static_cast<std::size_t>(client.getMSS())};
				Stream::Security::TLS tls{ctx};
				client <=> buffer <=> tls;

				std::string request;
				request.resize(MAX_HTTP_BUFFER_SIZE);
				request.resize(tls.readSome(request.data(), request.size()));
				std::cout << request << std::endl;

				std::string c = std::to_string(reqNumber);
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
	return 0;
}
