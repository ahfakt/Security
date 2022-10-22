#include <Stream/Socket.hpp>
#include <StreamSecurity/TLS.hpp>
#include <iostream>

#define MAX_HTTP_BUFFER_SIZE 64*1024

int main() {
	Stream::Socket server{Stream::Socket::Address::Inet{"api.binance.com", 443}};
	Stream::Buffer buffer{static_cast<std::size_t>(server.getMSS())};
	Stream::Security::TLS tls{Stream::Security::TLS::Context{TLS_client_method()}};
	server <=> buffer <=> tls;

	std::string request{
		"GET /api/v3/ticker/price?symbol=ETHUSDT HTTP/1.1\r\n"
		"Host: api.binance.com\r\n"
		"Accept-Encoding: text/json\r\n"
		"Connection: close\r\n\r\n"
	};

	tls.write(request.data(), request.size());
	std::string response;
	response.resize(MAX_HTTP_BUFFER_SIZE);
	response.resize(tls.readSome(response.data(), response.size()));
	std::cout << response.data() << std::endl;

	return 0;
}
