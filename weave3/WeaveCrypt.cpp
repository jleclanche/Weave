#include "WeaveCrypt.h"

namespace Weave {
	namespace Crypt {
		void init(RC4_KEY* rc4, const unsigned char* session_key, const unsigned char* peer_key)
		{
			HMAC_CTX hmac_ctx;
			HMAC_CTX_init(&hmac_ctx);
			HMAC_Init_ex(&hmac_ctx, (void*)peer_key, peer_key_size, EVP_sha1(), NULL);

			HMAC_Update(&hmac_ctx, session_key, session_key_size);

			unsigned char rc4_keystring[SHA_DIGEST_LENGTH];
			unsigned int rc4_keystring_size = SHA_DIGEST_LENGTH;
			
			HMAC_Final(&hmac_ctx, rc4_keystring, &rc4_keystring_size);
			
			HMAC_CTX_cleanup(&hmac_ctx);

			RC4_set_key(rc4, rc4_keystring_size, rc4_keystring);
			
			const unsigned char rc4_key_init[rc4_init_size] = { 0x00 };
			unsigned char rc4_key_init_output[rc4_init_size];

			RC4(rc4, sizeof(rc4_key_init), rc4_key_init, rc4_key_init_output);
		}
		
		void peek(const RC4_KEY* rc4, size_t size, const unsigned char* source, unsigned char* dest)
		{
			RC4_KEY kcpy;
			memcpy(&kcpy, rc4, sizeof(RC4_KEY));
			RC4(&kcpy, size, source, dest);
		}
	}
}
