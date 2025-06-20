#include "headers/webhook_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "headers/secrets.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")


int send_webhook(const char *msg, const char *description, int color, const char *title)
{
	if(color == NULL){
		color = 16711680;
	}
	if(title == NULL){
		title = "EvilEye";
	}
	if(description == NULL){
		printf("No description provided must use a description\n");
		return 1;
	}
	if(msg == NULL){
		msg = "";
	}
	
	WSADATA wsaData;
	SOCKET sock = INVALID_SOCKET;
	struct addrinfo hints = {0}, *res = NULL;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		perror("WSA STARTUP FAILED");
		exit(EXIT_FAILURE);
	}

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(HOST, PORT, &hints, &res) != 0)
	{
		perror("DNS RESOLUTION FAILED");
		WSACleanup();
		exit(EXIT_FAILURE);
	}

	sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	if (connect(sock, res->ai_addr, (int)res->ai_addrlen) != 0)
	{
		perror("SOCKET CONNECTION FAILED");
		closesocket(sock);
		freeaddrinfo(res);
		WSACleanup();
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(res);

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx)
	{
		perror("SSL_CTX_NEW FAILED");
		closesocket(sock);
		WSACleanup();
		exit(EXIT_FAILURE);
	}
	ssl = SSL_new(ctx);
	if (!ssl)
	{
		perror("SSL_NEW FAILED");
		SSL_CTX_free(ctx);
		closesocket(sock);
		WSACleanup();
	}

	SSL_set_fd(ssl, (int)sock);
	if (SSL_connect(ssl) <= 0)
	{
		perror("SSL_CONNECT FAILED");
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		closesocket(sock);
		WSACleanup();
		exit(EXIT_FAILURE);
	}


	char request[4096];

	char payload[2048];
	snprintf(payload, sizeof(payload),
			 "{"
			 "\"content\": \"%s\","
			 "\"embeds\": ["
			 "{"
			 "\"title\": \"%s\","
			 "\"description\": \"%s\","
			 "\"color\": %d"
			 "}"
			 "]"
			 "}",
			 msg, title, description, color);
	snprintf(request, sizeof(request),
			 "POST %s HTTP/1.1\r\n"
			 "Host: %s\r\n"
			 "Content-Type: application/json\r\n"
			 "Content-Length: %zu\r\n"
			 "Connection: close\r\n"
			 "\r\n"
			 "%s",
			 URL, HOST, strlen(payload), payload

	);
	if (SSL_write(ssl, request, (int)strlen(request)) <= 0)
	{
		perror("SSL_WRITE FAILED");
		SSL_shutdown(ssl);
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		closesocket(sock);
		WSACleanup();
		exit(EXIT_FAILURE);
	}

	char buffer[4096];
	int bytes;
	while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0)
	{
		buffer[bytes] = '\0';
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	closesocket(sock);
	WSACleanup();
	freeaddrinfo(res);

	return 0;
}
