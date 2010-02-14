#ifndef WEAVE_CRYPT_H
#define WEAVE_CRYPT_H

#include <string.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rc4.h>

namespace Weave {
	
	namespace Crypt {
		static const size_t session_key_size = 40;
		static const size_t peer_key_size = 16;
		static const size_t rc4_init_size = 1024;

		static const unsigned char client_key[] = { 
			0xF4, 0x66, 0x31, 0x59, 0xFC, 0x83, 0x6E, 0x31, 0x31, 0x02, 0x51,
			0xD5, 0x44, 0x31, 0x67, 0x98
		};

		static const unsigned char server_key[] = {
			0x22, 0xBE, 0xE5, 0xCF, 0xBB, 0x07, 0x64, 0xD9, 0x00, 0x45, 0x1B,
			0xD0, 0x24, 0xB8, 0xD5, 0x45
		};

		void init(RC4_KEY* rc4, const unsigned char* session_key, const unsigned char* peer_key);
		void peek(const RC4_KEY* rc4, size_t size, const unsigned char* source, unsigned char* dest);
	}
}

#endif /* WEAVE_CRYPT_H */
