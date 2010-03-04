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
 * Message handling.
 */

#include "weave.h"

/** Process a message sent from the client to the server (CMSG).
 *  
 *  Note that NIDS names the data streams after their destination, not their
 *  source, which is why the half-stream that we're accessing in this
 *  function is called stream->server for CMSGs. */
void cmsg_process(struct tcp_stream* stream, conn_param** param_ptr)
{
	conn_param* param = *param_ptr;
	int count_new = stream->server.count_new; 	/* Number of new bytes in the
												   buffer since last function
												   call to cmsg_process */
	int first_message = stream->server.count == count_new;	/* Boolean value
															   indicating
															   whether this is
															   the first CMSG */

	wlog(3, "Received %d bytes from Client\n", count_new);

	/* Pointer to the new data bytes */
	char* data_new = stream->server.data;

	/* The new data bytes interpreted as a CMSG header */
	cmsg_header* header = (cmsg_header*) data_new;

	if(!param->type)
	{
		/* We don't know yet what kind of connection this is, so we have to
		   take a guess. */
		if(first_message)
		{
			/* This is the first message sent from the client. We're going to
			   perform a few checks to see if this could be a login challenge */
			int valid_lc = 1;
			cmsg_login_challenge* check_lc = (cmsg_login_challenge*) data_new;

			if(count_new > sizeof(cmsg_login_challenge))
			{
				/* Check whether the size specified in the header matches the
				   real packet size. */
				if(check_lc->header.size != count_new - sizeof(check_lc->header)) // FIXME: endianess
				{
					valid_lc = 0;
				}

				/* Check whether this is "WoW\x00" (live game client) or "TWoW"
				   (PTR builds). If this matches, we can be fairly certain it's
				   an auth connection. */
				if(valid_lc && memcmp(check_lc->game, "TWoW", 4) && memcmp(check_lc->game, "WoW", 3))
				{
					valid_lc = 0;
				}
			} else
				valid_lc = 0;	/* This packet is too short to be a login
								   challenge. */

			if(valid_lc)
			{
				param->type = CT_AUTH;

				param->account = calloc(1, check_lc->name_size + 1);
				assert(param->account != NULL);
				strncpy(param->account, data_new + sizeof(cmsg_login_challenge),
					check_lc->name_size);

				wlog(2, "Recognized auth connection\n");
				wlog(3, "Auth connection account name: %s\n", param->account);
			} else {
				return conn_discard(stream, param_ptr, "Invalid login challenge");
			}
		}
	}

	if(param->type == CT_GAME)
	{
		/* We know that this is a game connection (the detection for this is
		   done in smsg_process). */
		packet* p = packet_append(&param->server.packet_sequence);
		gettimeofday(&p->time, NULL);
		p->source = PS_CLIENT;
		p->data = malloc(count_new);
		assert(p->data != NULL);
		memcpy(p->data, stream->server.data, count_new);

		p->size = count_new;
		p->encrypted = param->encrypted;
		p->conn = (void*) param;
		p->next = NULL;

		wlog(3, "Appended client message of %d bytes at 0x%X\n", p->size, p);

		if(param->encrypted)
		{
			if(1) // (!param->have_key)
			{
				cbc_decrypt(stream->server.data, sizeof(cmsg_header), &param->server.cbc_iv_kg);
				cmsg_gather_key(stream->server.data, count_new, param_ptr);
			}

			if(param->have_key)
			{
				msg_decrypt_all(param);
				msg_dump_all(param);
			}
		} else {
			/* This connection is not encrypted. Check whether the opcode is
			   the one for CMSG_AUTH_SESSION. */
			if(header->opcode == 0x1ED) /* CMSG Auth Session */
			{
				/* The Auth Session packet tells the server which client it's
				   dealing with. From this point, both parties know the shared
				   secret (the key) that has been established upon login, and
				   further communication is done over an encrypted connection.*/

				wlog(1, "Connection is now encrypted\n");
				wlog(1, "Decryption of packets will be delayed until the full key is available\n");
				param->encrypted = 1;
				param->build = *((uint16_t*) (data_new+sizeof(cmsg_header)));

				char* account_ptr = data_new+sizeof(cmsg_header)+8;
				int account_size = strlen(account_ptr);
				if(account_ptr + account_size < data_new + count_new)
				{
					param->account = calloc(1, account_size+1);
					if(param->account != NULL)
						strncpy(param->account, account_ptr, account_size);
				}

				if(param->account != NULL)
					wlog(2, "Client build: %d - Account name: %s\n", param->build, param->account);
				else
					wlog(2, "Client build: %d - Account name invalid\n", param->build);
				
				if(msg_enable_logging)
				{
					param->log_to = msg_log_create(param->account);
					msg_dump_header(param->log_to);
				}
			}

			msg_dump(p);
			msg_remove(&param->server.packet_sequence, p);
		}
	}
}

/** Process a message sent from the server to the client (SMSG). Many of the
 *  details given in cmsg_process apply here as well, but there are a few
 *  notable differences.
 *  
 *  Again, note that NIDS names the data streams after their destination, not
 *  their source, which is why the half-stream that we're accessing in this
 *  function is called stream->client for SMSGs. */
void smsg_process(struct tcp_stream* stream, conn_param** param_ptr)
{
	conn_param* param = *param_ptr;
	int count_new = stream->client.count_new;	/* Number of new bytes in the
												   buffer since last function
												   call to smsg_process */

	wlog(3, "Received %d bytes from Server\n", count_new);

	/* Pointer to the new data bytes */
	char* data_new = stream->client.data;

	/* The new data bytes interpreted as a SMSG header */
	smsg_header* header = (smsg_header*) data_new;

	if(!param->type)
	{
		/* We don't know yet what kind of connection this is, so we have to
		   take a guess. We check whether the opcode in this message is the one
		   for an Auth Challenge, which is the first SMSG sent to the game
		   client once it has connected to a game server.
		   In this auth challenge, the server requests the session ID that the
		   client has established upon login. */
		if(header->opcode == 0x1EC) // FIXME: endianess
		{
			wlog(2, "Recognized game connection\n");
			param->type = CT_GAME;
		} else {
			wlog(3, "Unknown opcode %d in smsg_process()\n", header->opcode);
			return conn_discard(stream, param_ptr, "Unknown opcode");
		}
	}

	if(param->type == CT_GAME)
	{
		packet* p = packet_append(&param->client.packet_sequence);
		gettimeofday(&p->time, NULL);
		p->source = PS_SERVER;
		p->data = malloc(count_new);
		assert(p->data != NULL);
		memcpy(p->data, data_new, count_new);
		p->encrypted = param->encrypted;
		p->size = count_new;
		p->next = NULL;
		p->conn = (void*) param;

		wlog(3, "Appended server message of %d bytes at 0x%X\n", p->size, p);

		if(param->encrypted)
		{
			/* The connection is encrypted (which is in fact quite likely, since
			   only the first message is sent in plain). */
			if(param->have_key)
			{
				msg_decrypt_all(param);
				msg_dump_all(param);
			}
		} else {
			/* Not encrypted */
			msg_dump(p);
			msg_remove(&param->client.packet_sequence, p);
		}
	}
}

/** Allocates memory for a new packet structure and appends it to the end of
 *  the given \a sequence.
 *
 *  \param[in] sequence The sequence at whose end the new structure will be
 *  appended.
 *  \return Pointer to the newly allocated packet structure. */
packet* packet_append(packet** sequence)
{
	if(*sequence)
	{
		do {
			sequence = (packet**) &((*sequence)->next);
		} while(*sequence);
	}

	*sequence = (packet*) calloc(1, sizeof(packet));
	assert(*sequence != NULL);

	return *sequence;
}

packet* msg_remove(packet** begin, packet* p)
{
	packet** search = begin;

	while(*search != NULL && *search != p)
		search = (packet**) &((*search)->next);

	assert(*search != NULL);
	*search = (packet*) p->next;

	free(p->data);
	free(p);

	return *search;
}

/** Decrypts all the packets in both client and server sequences which are
 *  still encrypted. */
void msg_decrypt_all(conn_param* param)
{
	packet* p_server = param->server.packet_sequence;
	packet* p_client = param->client.packet_sequence;

	while(p_server != NULL)
	{
		if(p_server->encrypted) 
			msg_decrypt(param, p_server);

		if(!msg_correct_size(p_server))
			/** If the message size is not correct, halt decryption of the
			 *  sequence until the next call to msg_decrypt_all() */
			break;

		p_server = (packet*) p_server->next;
	}

	while(p_client != NULL)
	{
		if(p_client->encrypted)
			msg_decrypt(param, p_client);

		if(!msg_correct_size(p_client))
			break;

		p_client = (packet*) p_client->next;
	}
}

/** Outputs all the packets in both client and server sequences and removes them
 */
void msg_dump_all(conn_param* param)
{
	packet* p_server;
	packet* p_client;

	int passes = 0;

	do
	{
		p_server = param->server.packet_sequence;
		p_client = param->client.packet_sequence;

		if(p_server)
		{
			if(!p_server->encrypted && p_server->nominal_size == p_server->size)
			{
				if(p_client == NULL || p_server->time.tv_sec < p_client->time.tv_sec || (p_server->time.tv_sec == p_client->time.tv_sec && p_server->time.tv_usec <= p_client->time.tv_usec))
				{
					msg_dump(p_server);
					p_server = msg_remove(&param->server.packet_sequence, p_server);
					continue;
				}
			} else {
				/** If an encrypted packet or a wrong size is encountered,
				 *  halt the output of this sequence until the next pass. */
				wlog(3, "Not dumping CMSG 0x%X (encrypted = %d, nominal size = %d, real size = %d)\n", p_server, p_server->encrypted, p_server->nominal_size, p_server->size);
				p_server = NULL;
				p_client = NULL;
			}
		}

		if(p_client)
		{
			if(!p_client->encrypted && p_client->nominal_size == p_client->size)
			{
				if(p_server == NULL || p_client->time.tv_sec < p_server->time.tv_sec || (p_client->time.tv_sec == p_server->time.tv_sec && p_client->time.tv_usec <= p_server->time.tv_usec))
				{
					msg_dump(p_client);
					p_client = msg_remove(&param->client.packet_sequence, p_client);
					continue;
				}
			} else {
				wlog(3, "Not dumping SMSG 0x%X (encrypted = %d, nominal size = %d, real size = %d)\n", p_client, p_client->encrypted, p_client->nominal_size, p_client->size);
				p_client = NULL;
				p_server = NULL;
			}
		}

		/* Occasionally, this gets stuck in an infinite loop, but I've not yet
		   been able to reproduce it. Not sure if this prevents the issue from
		   eating your CPU, but better than nothing. */
		passes ++;
		assert(passes < 2048);
	} while(p_server || p_client);
}

/** Correct the size of a packet, splitting or merging the packets as necessary
 * \return 1 if the packet's size is correct, 0 if there is not enough data to
 * fill the size specified in the header. */
int msg_correct_size(packet* p)
{
	if(p->nominal_size < p->size)
	{
		/* The packet header says that this packet is not as long as the buffer
		   that holds it, which means that there is another packet at the end of
		   it.

		   In this case, we split the packet into two pieces using some memory
		   magic. */

		/* We allocate memory for a new packet structure. */
		packet* newp = calloc(1, sizeof(packet));
		assert(newp != NULL);

		/* This new packet structure begins at the end of the last packet and
		   continues until the end of the buffer. */
		newp->size = p->size - p->nominal_size;

		/* We copy the overhead of the old packet into the buffer of the new
		   one before truncating the old packet to it's real length. */
		newp->data = malloc(newp->size);
		assert(newp->data != NULL);
		memcpy(newp->data, p->data + p->nominal_size, newp->size);

		p->size = p->nominal_size;
		p->data = realloc(p->data, p->size);
		assert(p->data != NULL);

		/* The new packet inherits some of its data from the old one. */
		newp->time = p->time;
		newp->source = p->source;
		newp->conn = p->conn;

		/* Since we just discovered this packet, it has not been decrypted yet
		   and will be decrypted by msg_decrypt_all() during next pass. */
		newp->encrypted = 1;

		/* Insert the new packet after the old one. */
		wlog(3, "Correcting size of MSG 0x%X to %d bytes by splitting off MSG 0x%X of %d bytes\n", p, p->size, newp, newp->size);
		newp->next = p->next;
		p->next = (void*) newp;

	} else while (p->nominal_size > p->size) {
		/* This is the opposite case from above: The packet header says that
		   this packet is longer than our data buffer.

		   This means that we're lacking data. This might have happened due to
		   ethernet fragmentation into chunks of 1460. We'll try to merge the
		   following packets into this one to get enough data. */

		/* Find the next packet in the sequence. */
		packet* nextp = (packet*) p->next;
		if(!nextp)
		{
			/* There is no next packet that we could steal data from, which
			   means that we still have an incomplete packet now.
			   There's nothing more we can do, so we return 0 to let our caller
			   know something went wrong. It should try again once more data is
			   available. */
			wlog(3, "No more messages while correcting MSG 0x%X to %d bytes; will try again next round (%d bytes missing)\n", p, p->nominal_size, (p->nominal_size-p->size));
			return 0;
		}

		int slice = p->nominal_size - p->size;
		if(slice >= nextp->size)
			/* The next packet isn't large enough to fill this one, but we're
			   slicing off as many bytes as possible (i.e. the whole packet). */
			slice = nextp->size;

		/* Increase this packet's size and copy the data into the right place.*/
		p->size += slice;
		p->data = realloc(p->data, p->size);
		assert(p->data != NULL);
		memcpy(p->data + p->size - slice, nextp->data, slice);

		/* The next packet's size is reduced by the amount we just appended to
		   the old packet. */
		nextp->size -= slice;

		wlog(3, "Correcting size of MSG 0x%X to %d bytes by merging in %d bytes of MSG 0x%X\n", p, p->size, slice, nextp);
		if(nextp->size > 0)
		{
			/* After clipping of the bytes, the next packet still has data left,
			   so we need to keep it around and remove what we just appended to
			   the old packet. Otherwise, we would have duplicated the data. */
			char* newdata = malloc(nextp->size);
			assert(newdata != NULL);
			memcpy(newdata, nextp->data + slice, nextp->size);
			free(nextp->data);
			nextp->data = newdata;
		} else {
			/* If the next packet was fully merged into this one, we can safely
			   remove it and free the associated memory. */
			wlog(3, "MSG 0x%X fully merged into 0x%X, removing.\n", nextp, p);
			p->next = nextp->next;
			free(nextp->data);
			free(nextp);
		}
	}

	return 1;
}
