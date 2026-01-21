#include <common.h>
#include <constexpr.h>
#include <memory.h>
#include <resolve.h>
#include <prng.h>
#include <sha256.h>
#include <x25519.h>
#include <chacha20.h>
#include <pbkdf2.h>

using namespace Crypto;

#define SERVER_PORT 4444
#define PBKDF2_DEMO_ITERATIONS 10000
#define MSG_BUFFER_SIZE 512

#define AF_INET 2
#define SOCK_STREAM 1
#define IPPROTO_TCP 6
#define INADDR_ANY 0
#define INVALID_SOCKET (~0ULL)
#define SOCKET_ERROR (-1)

struct my_sockaddr_in {
	uint16_t sin_family;
	uint16_t sin_port;
	uint32_t sin_addr;
	char     sin_zero[8];
};

struct MessageFrame {
	uint32_t length;
	uint8_t  nonce[12];
	uint8_t  data[MSG_BUFFER_SIZE];
};

declfn auto instance::print_hex(
	_In_ instance*      ctx,
	_In_ const char*    label,
	_In_ const uint8_t* data,
	_In_ size_t         len) -> void {
	char   hex_buf[128];
	size_t hex_offset = 0;

	size_t print_len = len > 32 ? 32 : len;
	for (size_t i = 0; i < print_len && hex_offset + 3 < sizeof(hex_buf); i++) {
		const char hex_chars[] = "0123456789abcdef";
		hex_buf[hex_offset++] = hex_chars[(data[i] >> 4) & 0xF];
		hex_buf[hex_offset++] = hex_chars[data[i] & 0xF];
		if (i < print_len - 1) { hex_buf[hex_offset++] = ' '; }
	}
	hex_buf[hex_offset] = '\0';

	DPRINT_CTX (ctx, "%s: %s%s\n", label, hex_buf, len > 32 ? "..." : "");
}

declfn auto instance::demo_prng(_In_ instance* ctx) -> void {
	DPRINT_CTX (ctx, "=== PRNG ===\n");

	uint8_t random_bytes[32];
	secure_random_bytes (ctx, random_bytes, 32);

	print_hex (ctx, STRING ("PRNG output (32 bytes)"), random_bytes, 32);

	uint8_t random_bytes2[32];
	secure_random_bytes (ctx, random_bytes2, 32);

	print_hex (ctx, STRING ("PRNG output 2 (32 bytes)"), random_bytes2, 32);

	memory::secure_erase (random_bytes, sizeof(random_bytes));
	memory::secure_erase (random_bytes2, sizeof(random_bytes2));
}

declfn auto instance::demo_sha256(_In_ instance* ctx) -> void {
	DPRINT_CTX (ctx, "=== SHA256 ===\n");

	const char* test_msg = symbol<const char *> ("Hello, World");
	uint8_t     hash[SHA256_HASH_SIZE];

	sha256 (reinterpret_cast<const uint8_t *> (test_msg), memory::strlen (test_msg), hash);

	DPRINT_CTX (ctx, "Input: \"%s\"\n", test_msg);
	print_hex (ctx, STRING ("SHA256 hash"), hash, SHA256_HASH_SIZE);

	memory::secure_erase (hash, sizeof(hash));
}

declfn auto instance::demo_x25519(_In_ instance* ctx) -> void {
	DPRINT_CTX (ctx, "=== X25519 ===\n");

	uint8_t alice_pub[X25519_KEY_SIZE], alice_priv[X25519_KEY_SIZE];
	uint8_t bob_pub[X25519_KEY_SIZE],   bob_priv[X25519_KEY_SIZE];

	x25519_generate_keypair (ctx, alice_pub, alice_priv);
	x25519_generate_keypair (ctx, bob_pub, bob_priv);

	print_hex (ctx, STRING ("Alice public key"), alice_pub, X25519_KEY_SIZE);
	print_hex (ctx, STRING ("Bob public key"), bob_pub, X25519_KEY_SIZE);

	uint8_t alice_shared[X25519_KEY_SIZE], bob_shared[X25519_KEY_SIZE];
	x25519_shared_secret (alice_shared, alice_priv, bob_pub);
	x25519_shared_secret (bob_shared, bob_priv, alice_pub);

	print_hex (ctx, STRING ("Alice shared secret"), alice_shared, X25519_KEY_SIZE);
	print_hex (ctx, STRING ("Bob shared secret"), bob_shared, X25519_KEY_SIZE);

	bool match = constant_time_equals (alice_shared, bob_shared, X25519_KEY_SIZE);
	DPRINT_CTX (ctx, "Shared secrets match: %s\n", match ? STRING("YES") : STRING("NO"));

	memory::secure_erase (alice_priv, sizeof(alice_priv));
	memory::secure_erase (bob_priv, sizeof(bob_priv));
	memory::secure_erase (alice_shared, sizeof(alice_shared));
	memory::secure_erase (bob_shared, sizeof(bob_shared));
}

declfn auto instance::demo_chacha20_poly1305(_In_ instance* ctx) -> void {
	DPRINT_CTX (ctx, "=== ChaCha20-Poly1305 ===\n");

	HANDLE hHeap = ctx->kernel32.GetProcessHeap();

	uint8_t key[CHACHA20_KEY_SIZE];
	uint8_t nonce[CHACHA20_NONCE_SIZE];
	secure_random_bytes (ctx, key, CHACHA20_KEY_SIZE);
	secure_random_bytes (ctx, nonce, CHACHA20_NONCE_SIZE);

	const char* plaintext = symbol<const char *> ("hihi!!!!!!");
	size_t      pt_len = memory::strlen (plaintext);

	uint8_t* ciphertext = (uint8_t *)ctx->kernel32.HeapAlloc (hHeap, 8, 128);
	uint8_t* decrypted = (uint8_t *)ctx->kernel32.HeapAlloc (hHeap, 8, 128);
	uint8_t  tag[POLY1305_TAG_SIZE];

	if (!ciphertext || !decrypted) {
		if (ciphertext) ctx->kernel32.HeapFree (hHeap, 0, ciphertext);
		if (decrypted) ctx->kernel32.HeapFree (hHeap, 0, decrypted);
		return;
	}

	DPRINT_CTX (ctx, "Plaintext: \"%s\"\n", plaintext);

	chacha20_poly1305_encrypt (
	                           key, nonce,
	                           nullptr, 0,
	                           reinterpret_cast<const uint8_t *> (plaintext), pt_len,
	                           ciphertext, tag);

	print_hex (ctx, STRING ("Ciphertext"), ciphertext, pt_len);
	print_hex (ctx, STRING ("Auth tag"), tag, POLY1305_TAG_SIZE);

	bool valid = chacha20_poly1305_decrypt (
	                                        key, nonce,
	                                        nullptr, 0,
	                                        ciphertext, pt_len,
	                                        tag, decrypted);

	if (valid) {
		decrypted[pt_len] = '\0';
		DPRINT_CTX (ctx, "Decryption valid: YES\n");
		DPRINT_CTX (ctx, "Decrypted: \"%s\"\n", reinterpret_cast<char*>(decrypted));
	} else { DPRINT_CTX (ctx, "Decryption valid: NO\n"); }

	memory::secure_erase (key, sizeof(key));
	memory::secure_erase (nonce, sizeof(nonce));
	memory::secure_erase (ciphertext, 128);
	memory::secure_erase (decrypted, 128);
	ctx->kernel32.HeapFree (hHeap, 0, ciphertext);
	ctx->kernel32.HeapFree (hHeap, 0, decrypted);
}

declfn auto instance::send_encrypted(
	_In_ instance*      ctx,
	_In_ uintptr_t      socket,
	_In_ const uint8_t* key,
	_In_ const uint8_t* nonce_base,
	_Inout_ uint64_t*   counter,
	_In_ const char*    message) -> bool {
	size_t msg_len = memory::strlen (message);
	if (msg_len > MSG_BUFFER_SIZE - POLY1305_TAG_SIZE - 16) return false;

	uint8_t nonce[CHACHA20_NONCE_SIZE];
	memory::copy (nonce, nonce_base, CHACHA20_NONCE_SIZE);

	for (int i = 0; i < 8; i++) { nonce[i] ^= static_cast<uint8_t> ((*counter >> (i * 8)) & 0xFF); }
	(*counter)++;

	MessageFrame frame;
	memory::set (&frame, 0, sizeof(frame));
	memory::copy (frame.nonce, nonce, CHACHA20_NONCE_SIZE);

	uint8_t tag[POLY1305_TAG_SIZE];
	chacha20_poly1305_encrypt (
	                           key, nonce,
	                           nullptr, 0,
	                           reinterpret_cast<const uint8_t *> (message), msg_len,
	                           frame.data, tag);

	memory::copy (frame.data + msg_len, tag, POLY1305_TAG_SIZE);

	frame.length = static_cast<uint32_t> (CHACHA20_NONCE_SIZE + msg_len + POLY1305_TAG_SIZE);

	int sent = ctx->ws2_32.send (socket, reinterpret_cast<char *> (&frame.length), 4, 0);
	if (sent != 4) return false;

	sent = ctx->ws2_32.send (socket, reinterpret_cast<char *> (frame.nonce), frame.length, 0);
	if (sent != static_cast<int> (frame.length)) return false;

	memory::secure_erase (&frame, sizeof(frame));
	memory::secure_erase (nonce, sizeof(nonce));
	return true;
}

declfn auto instance::recv_encrypted(
	_In_ instance*      ctx,
	_In_ uintptr_t      socket,
	_In_ const uint8_t* key,
	_Out_ char*         message,
	_In_ size_t         max_len) -> int {
	uint32_t frame_len = 0;
	int      received = ctx->ws2_32.recv (socket, reinterpret_cast<char *> (&frame_len), 4, 0);
	if (received != 4 || frame_len < CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE) return -1;
	if (frame_len > MSG_BUFFER_SIZE) return -1;

	HANDLE hHeap = ctx->kernel32.GetProcessHeap();

	uint8_t* buffer = (uint8_t *)ctx->kernel32.HeapAlloc (hHeap, 8, MSG_BUFFER_SIZE);
	uint8_t* plaintext = (uint8_t *)ctx->kernel32.HeapAlloc (hHeap, 8, MSG_BUFFER_SIZE);

	if (!buffer || !plaintext) {
		if (buffer) ctx->kernel32.HeapFree (hHeap, 0, buffer);
		if (plaintext) ctx->kernel32.HeapFree (hHeap, 0, plaintext);
		return -1;
	}

	received = ctx->ws2_32.recv (socket, reinterpret_cast<char *> (buffer), frame_len, 0);
	if (received != static_cast<int> (frame_len)) {
		memory::secure_erase (buffer, MSG_BUFFER_SIZE);
		memory::secure_erase (plaintext, MSG_BUFFER_SIZE);
		ctx->kernel32.HeapFree (hHeap, 0, buffer);
		ctx->kernel32.HeapFree (hHeap, 0, plaintext);
		return -1;
	}

	uint8_t nonce[CHACHA20_NONCE_SIZE];
	memory::copy (nonce, buffer, CHACHA20_NONCE_SIZE);

	size_t   ct_len = frame_len - CHACHA20_NONCE_SIZE - POLY1305_TAG_SIZE;
	uint8_t* ciphertext = buffer + CHACHA20_NONCE_SIZE;
	uint8_t* tag = ciphertext + ct_len;

	bool valid = chacha20_poly1305_decrypt (
	                                        key, nonce,
	                                        nullptr, 0,
	                                        ciphertext, ct_len,
	                                        tag, plaintext);

	int result_len = -1;
	if (valid) {
		size_t copy_len = ct_len < max_len - 1 ? ct_len : max_len - 1;
		memory::copy (message, plaintext, copy_len);
		message[copy_len] = '\0';
		result_len = static_cast<int> (ct_len);
	}

	memory::secure_erase (buffer, MSG_BUFFER_SIZE);
	memory::secure_erase (plaintext, MSG_BUFFER_SIZE);
	memory::secure_erase (nonce, sizeof(nonce));
	ctx->kernel32.HeapFree (hHeap, 0, buffer);
	ctx->kernel32.HeapFree (hHeap, 0, plaintext);

	return result_len;
}

extern "C" auto declfn entry(_In_ void* args) -> void {
	instance ctx;
	ctx.start (args);

}

declfn instance::instance() {
	base.address = RipEntry();
	base.length = (RipData() - base.address) + END_OFFSET;

	ntdll.handle = resolve::module (expr::hash_string<wchar_t> (L"ntdll.dll"));
	kernel32.handle = resolve::module (expr::hash_string<wchar_t> (L"kernel32.dll"));
	kernelbase.handle = resolve::module (expr::hash_string<wchar_t> (L"kernelbase.dll"));

	RESOLVE_IMPORT (ntdll);
	RESOLVE_IMPORT (kernel32);
	RESOLVE_IMPORT (kernelbase);

	if (auto ws2_32_lib = kernel32.LoadLibraryA (symbol<const char *> ("ws2_32.dll"))) {
		ws2_32.handle = reinterpret_cast<uintptr_t> (ws2_32_lib);
		RESOLVE_IMPORT (ws2_32);
	} else {
		DPRINT ("Failed to load ws2_32.dll\n");
		return;
	}

	if (auto user32_lib = kernel32.LoadLibraryA (symbol<const char *> ("user32.dll"))) {
		user32.handle = reinterpret_cast<uintptr_t> (user32_lib);
		RESOLVE_IMPORT (user32);
	} else {
		DPRINT ("Failed to load user32.dll\n");
		return;
	}

	is_running = true;
}

declfn auto instance::start(_In_ void* args) -> void {
	DPRINT ("=== Crypto - Server ===\n\n");

	demo_prng (this);
	DPRINT ("\n");
	demo_sha256 (this);
	DPRINT ("\n");
	demo_x25519 (this);
	DPRINT ("\n");
	demo_chacha20_poly1305 (this);
	DPRINT ("\n");

	DPRINT ("=== Starting TCP Server on port %d ===\n", SERVER_PORT);

	uint8_t wsa_data[512];
	memory::set (wsa_data, 0, sizeof(wsa_data));
	int result = ws2_32.WSAStartup (0x0202, reinterpret_cast<LPWSADATA> (wsa_data));
	if (result != 0) {
		DPRINT ("WSAStartup failed: %d\n", result);
		return;
	}

	uintptr_t listen_socket = ws2_32.socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listen_socket == INVALID_SOCKET) {
		DPRINT ("socket() failed\n");
		ws2_32.WSACleanup();
		return;
	}

	sockaddr_in addr;
	memory::set (&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.S_un.S_addr = INADDR_ANY;
	addr.sin_port = ws2_32.htons (SERVER_PORT);

	result = ws2_32.bind (listen_socket, reinterpret_cast<const struct sockaddr *> (&addr), sizeof(addr));
	if (result == SOCKET_ERROR) {
		DPRINT ("bind() failed\n");
		ws2_32.closesocket (listen_socket);
		ws2_32.WSACleanup();
		return;
	}

	result = ws2_32.listen (listen_socket, 1);
	while (!result)
		if (result == SOCKET_ERROR) {
			DPRINT ("listen() failed\n");
			ws2_32.closesocket (listen_socket);
			ws2_32.WSACleanup();
			return;
		}

	DPRINT ("Server listening on port %d\n", SERVER_PORT);

	sockaddr_in client_addr;
	int         client_addr_len = sizeof(client_addr);
	uintptr_t   client_socket = ws2_32.accept (listen_socket,
	                                           reinterpret_cast<struct sockaddr *> (reinterpret_cast<char *> (&
		                                           client_addr)), &client_addr_len);
	while (client_socket == INVALID_SOCKET) {
		client_socket = ws2_32.accept (listen_socket,
		                               reinterpret_cast<struct sockaddr *> (reinterpret_cast<char *> (&client_addr)),
		                               &client_addr_len);
		kernel32.Sleep (1000);
	}

	DPRINT ("Client connected\n"); {
		uint8_t server_pub[X25519_KEY_SIZE], server_priv[X25519_KEY_SIZE];
		x25519_generate_keypair (this, server_pub, server_priv);

		print_hex (this, STRING ("Server public key"), server_pub, X25519_KEY_SIZE);

		int sent = ws2_32.send (client_socket, reinterpret_cast<char *> (server_pub), X25519_KEY_SIZE, 0);
		if (sent != X25519_KEY_SIZE) {
			DPRINT ("Failed to send server public key\n");
			memory::secure_erase (server_priv, sizeof(server_priv));
		} else {
			uint8_t client_pub[X25519_KEY_SIZE];
			int     recvd = ws2_32.recv (client_socket, reinterpret_cast<char *> (client_pub), X25519_KEY_SIZE, 0);
			if (recvd != X25519_KEY_SIZE) {
				DPRINT ("Failed to receive client public key\n");
				memory::secure_erase (server_priv, sizeof(server_priv));
			} else {
				print_hex (this, STRING ("Client public key"), client_pub, X25519_KEY_SIZE);

				uint8_t shared_secret[X25519_KEY_SIZE];
				x25519_shared_secret (shared_secret, server_priv, client_pub);

				print_hex (this, STRING ("Shared secret"), shared_secret, X25519_KEY_SIZE);

				uint8_t     session_key[CHACHA20_KEY_SIZE];
				uint8_t     nonce_base[CHACHA20_NONCE_SIZE];
				const char* salt = symbol<const char *> ("salty");

				derive_key_and_iv_from_shared_secret (
				                                      shared_secret, X25519_KEY_SIZE,
				                                      reinterpret_cast<const uint8_t *> (salt), memory::strlen (salt),
				                                      PBKDF2_DEMO_ITERATIONS,
				                                      session_key, CHACHA20_KEY_SIZE,
				                                      nonce_base, CHACHA20_NONCE_SIZE);

				print_hex (this, STRING ("Session key"), session_key, CHACHA20_KEY_SIZE);

				memory::secure_erase (shared_secret, sizeof(shared_secret));
				memory::secure_erase (server_priv, sizeof(server_priv));

				uint64_t nonce_counter = 0;

				DPRINT ("Key exchange complete, sending encrypted messages...\n\n");

				const char* msg1 = symbol<const char *> ("Hello from server");
				const char* msg2 = symbol<const char *> ("Encrypted with ChaCha20-Poly1305");
				const char* msg3 = symbol<const char *> ("END");
				const char* messages[] = { msg1, msg2, msg3 };

				for (int i = 0; i < 3; i++) {
					DPRINT ("Sending: \"%s\"\n", messages[i]);
					if (!send_encrypted (this, client_socket, session_key, nonce_base, &nonce_counter, messages[i])) {
						DPRINT ("Failed to send message %d\n", i);
						break;
					}

					char response[MSG_BUFFER_SIZE];
					int  len = recv_encrypted (this, client_socket, session_key, response, sizeof(response));
					if (len > 0) { DPRINT ("Received echo: \"%s\"\n\n", response); } else {
						DPRINT ("Failed to receive echo\n");
						break;
					}
				}

				memory::secure_erase (session_key, sizeof(session_key));
				memory::secure_erase (nonce_base, sizeof(nonce_base));
			}
		}
	}

	ws2_32.closesocket (client_socket);
	ws2_32.closesocket (listen_socket);
	ws2_32.WSACleanup();

	DPRINT ("Server shutting down.\n");
	kernel32.ExitProcess (0);
}
