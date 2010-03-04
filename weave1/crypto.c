/* 	This file is part of Weave.

	Weave is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	Weave is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Weave.  If not, see <http://www.gnu.org/licenses/>. */

/** \file
 * Functions for cryptographic analysis.
 */

#include "weave.h"

/** Decrypts the bytes in \a buffer using CBC (Chain Block Cipher). CBC is a
 *  simple encryption where the previous byte is subtracted from each byte.
 *
 *  This is the first stage of decryption and, for CMSGs, can be performed
 *  without the knowledge of the key. We can't, however, decrypt SMSGs with
 *  this unless we know the full key, since the server often packs several
 *  messages into one TCP/IP packet, which makes our computations faulty.
 *
 *  \param[in,out] buffer The buffer that is to be decrypted
 *  \param[in] size The number of bytes to decrypt
 *  \param[in,out] iv The Initialization Vector that is used as a reference for the
 *  first byte in the buffer */
void cbc_decrypt(char* buffer, int size, char* iv)
{
	int index;

	wlog(4, "0x%02X → CBC Input: ", (unsigned char)*iv);

	for(index = 0; index < size; index ++)
	{
		char tmp;
		tmp = buffer[index];
		wlog(4, "%02X ", (unsigned char)tmp);
		buffer[index] = buffer[index] - *iv;
		*iv = tmp;
	}

	wlog(4, ", Output: ");
	for(index = 0; index < size; index ++)
		wlog(4, "%02X ", (unsigned char) buffer[index]);
	wlog(4, " ? 0x%02X\n", (unsigned char)*iv);
}

/** Decrypt the bytes in \a buffer by XOR'ing them with \a key and the given
 *  \a key_offset.
 *  
 *  This is the second stage of decryption and has to be performed after the
 *  CBC decryption using cbc_decrypt().
 *
 *  \param[in,out] buffer The buffer that is to be decrypted
 *  \param[in] size The number of bytes to decrypt
 *  \param[in] key The key to be used for decryption
 *  \param[in,out] key_offset The current byte position within the key
 */
void xor_decrypt(char* buffer, int size, char* key, int* key_offset)
{
	int index;

	wlog(4, "%d → XOR Input: ", *key_offset);

	for(index = 0; index < size; index ++)
	{
		wlog(4, "%02X ", (unsigned char) buffer[index]);

		buffer[index] = buffer[index] ^ key[*key_offset];

		*key_offset = (*key_offset + 1) % 20;
	}

	wlog(4, ", Output: ");
	for(index = 0; index < size; index ++)
		wlog(4, "%02X ", (unsigned char) buffer[index]);
	wlog(4, " ? %d\n", *key_offset);
}

/** Using the known packet size, obtain two new key bytes from a client message.
 *
 *  \param[in,out] data The CBC-decrypted data that is to be used as input
 *  \param[in] size The known size of the packet
 *  \param[in,out] param_ptr Pointer to a pointer to a conn_param structure
 *  which will be updated with the new key bytes. */
void cmsg_gather_key(char* data, int size, conn_param** param_ptr)
{
	conn_param* param = *param_ptr;

	/* We don't have the full key yet, so we have to try to gather one. */
	int index;

	/* Pack the packet size into a 16-bit integer */
	uint16_t plain_size = htons(size-2); // FIXME: endianess?
	char* plain_bytes = (char*) &plain_size;

	char* key = param->key;
	int* key_offset = &param->server.key_offset_kg;

	/** What we do to obtain the key is to perform a known plaintext attack.
		We know how large the packet is, we know that the first two
		bytes always contain the packet size. Since the encryption is
		just a plain XOR, we can take advantage of the following:

			\f[ Cipher = Plaintext \oplus Key \f]
			\f[ Key = Cipher \oplus Plaintext \f]

		(with \f$ \oplus \f$ being the \e XOR operation)

		We simply XOR the encrypted data we receive with the data
		that we know they represent, and there we go - another two
		bytes of the key!

		The fact that client headers are always 6 bytes long (2 bytes
		length + 4 bytes opcode) causes the key offset to wrap to the
		other key bytes. Eventually, we know the full key. */

	for(index = 0; index < 2; index ++)
	{
		char nv = data[index] ^ plain_bytes[index];
		if(key[*key_offset] != nv)
		{
			wlog(2, "Updating key offset %d from 0x%02X to 0x%02X\n", *key_offset, (unsigned char) key[*key_offset], (unsigned char) nv);
			key[*key_offset] = nv;
		}
		*key_offset = (*key_offset + 1) % 20;
	}

	/* Since the four bytes containing the opcode have not been
	   decrypted, we need to manually advance the key offset. */
	*key_offset = (*key_offset + 4) % 20;

	if(!param->have_key && isatty(fileno(stderr)))
	{
		wlog(1, "\rObtaining Session Key: ");
		int o_index;
		int have_bytes = 0;
		for(o_index = 0; o_index < 20; o_index++)
		{
			if(key[o_index] || !(*key_offset))
			{
				wlog(1, "\x1b[7m%02X\x1b[0m", (unsigned char) (key[o_index]) );
				have_bytes ++;
			} else {
				wlog(1, "▒▒");
			}
		}

		wlog(1, "    %02d/20 bytes", have_bytes);
	}

	if(!param->have_key && *key_offset == 0)
	{
		/* Once the key offset has wrapped back to 0, the key is
		   complete. */
		wlog(1, "\nKey complete\n");

		param->have_key = 1;

		/* We have to reset the CBC initialization vector to 0x00 since
		   from now on, the "real" decryption begins and needs to start over. */
		param->server.cbc_iv = 0x00;
	}
}

/** Decrypts a message */
void msg_decrypt(conn_param* param, packet* p)
{
	int* key_offset;
	char* cbc_iv;
	int header_size;

	/* Depending on which peer sent the message, we need to use different key
	   offsets and CBC initialization vectors. */
	if(p->source == PS_CLIENT) {
		key_offset = &param->server.key_offset;
		cbc_iv = &param->server.cbc_iv;
		header_size = sizeof(cmsg_header);
	} else if(p->source == PS_SERVER) {
		key_offset = &param->client.key_offset;
		cbc_iv = &param->client.cbc_iv;
		header_size = sizeof(smsg_header);
	}

	cbc_decrypt(p->data, header_size, cbc_iv);
	xor_decrypt(p->data, header_size, param->key, key_offset);

	/** Extracts the first two bytes into the packet's nominal size */
	p->nominal_size = ntohs(*((uint16_t*) p->data)) + 2;

	wlog(3, "Decrypted %d bytes of MSG 0x%X, nominal size is %d bytes\n", header_size, p, p->nominal_size);

	p->encrypted = 0;
}
