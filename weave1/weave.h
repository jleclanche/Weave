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
 * Includes and structure definitions for Weave.
 */
#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#ifdef HAVE_INTTYPES_H
#	include <inttypes.h>
#else
#	ifdef HAVE_SYS_TYPES_H
#		include <sys/types.h>
#	endif
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <ctype.h>

#include <arpa/inet.h>

#include <nids.h>

#include <errno.h>
#include <assert.h>

#include <getopt.h>

#include "opcodes.h"

/** Enumeration for the type of a connection. WoW uses TCP Port 3724 for all
 *  connections; however, depending on what kind of server it is, different
 *  handling is required. */
enum conn_type {
	/** Unknown connection, whose type will be attempted to guess. */
	CT_UNKNOWN	= 0,
	/** Connection to an auth server */
	CT_AUTH		= 1,
	/** Connection to a game server */
	CT_GAME		= 2
};

/** Enumeration for the source of a packet. */
enum packet_source {
	/** This packet was sent by the client. */
	PS_CLIENT = 0,
	/** This packet was sent by the server. */
	PS_SERVER = 1
};

/** Structure for storing information about a packet.
 *
 *  This structure holds information that is relevant for decryption and output
 *  of a packet, such as the time and size when it was received. 
 */
typedef struct {
	enum packet_source source; 	/**< Where the packet comes from */
	struct timeval time;		/**< When the packet was received */
	char* data;					/**< Pointer to the data of the packet
								     (including header and payload) */
	int size;					/**< Size of data buffer */
	int nominal_size;			/**< The size that the packet header claims */
	int encrypted;				/**< Whether this packet was mangled by
								     msg_decrypt() before */
	struct packet* next;		/**< Pointer to the next packet */
	struct conn_param* conn;
} packet;

/** Structure for holding connection-specific cryptographic data. */
typedef struct {
	/** The type that this connection has been detected to be. */
	enum conn_type type;
	
	/** The 160-bit key that is used for decrypting this connection */
	char key[20];
	
	/** Boolean value indicating whether the connection is currently being
	 *  encrypted or not. */
	int encrypted;
	
	/** Boolean value indicating whether we have successfully obtained a key
	 *  we could use for decrypting this connection. */
	int have_key;
	
	/** Game client build number. */
	int build;
	
	/** Player account name. */
	char* account;
	
	FILE* log_to;
	
	struct {
		/** Current offset of the key that is used for decryption. */
		int key_offset;
		int key_offset_kg;
		
		/** Initialization vector for cbc_decrypt() */
		char cbc_iv;
		char cbc_iv_kg;
		
		/** Pointer to the first element of a linked list to which all packets
		    for this peer are appended, in order */
		packet* packet_sequence;
		
		uint32_t ip;
		uint16_t port;
	} server, client;
	
} conn_param;

#pragma pack(1)

/** Header definitions for checking the validity of a login challenge. */
typedef struct {
struct {
	uint8_t		cmd; 				/**< Command */
	uint8_t 	error; 				/**< Error number */
	uint16_t	size; 				/**< Size of the packet */
}				header;				/**< Packet header */
	char		game[4];			/**< Game name. Can either be "WoW\x00" for
									 *   live clients, or "TWoW" for PTR builds.
									 */
struct {
	uint8_t		major;				/**< Application major version number */
	uint8_t		minor;				/**< Application minor version number */
	uint8_t		revision;			/**< Application revision number */
}				version;			/**< Triple field for the game version */
	uint16_t	build;				/**< Application build number */
	char		architecture[4];	/**< System architecture */
	char		os[4];				/**< Operating system */
	char		locale[4];			/**< Locale */
	int32_t		utc_offset;			/**< System clock offset to UTC in minutes*/
	uint32_t	ip;					/**< IP address */
	uint8_t		name_size;			/**< Length of the account name field */
} cmsg_login_challenge;

/** Header definition for a client message (CMSG).
 *  
 *  A client message header is always 6 bytes long. */
typedef struct {
	/** 2-byte unsigned integer indicating the packet length */
	uint16_t size;
	/** 4-byte unsigned integer indicating the opcode */
	uint32_t opcode;
} cmsg_header;

/** Header definition for a server message (SMSG).
 *  
 *  A server message header is always 4 bytes long. */
typedef struct {
	/** 2-byte unsigned integer indicating the packet length */
	uint16_t size;
	/** 2-byte unsigned integer indicating the opcode */
	uint16_t opcode;
} smsg_header;

/* weave.c */
int main(int argc, char* argv[]);
void wlog(int level, const char *format, ...);
void msg_dump(packet* p);
int msg_dump_header(FILE* stream);
void hex_dump(void *data, int size);
FILE* msg_log_create(const char* account);
extern int msg_enable_logging;

/* crypto.c */
void cbc_decrypt(char* buffer, int size, char* iv);
void xor_decrypt(char* buffer, int size, char* key, int* key_offset);
void cmsg_gather_key(char* data, int size, conn_param** param_ptr);
void msg_decrypt(conn_param* param, packet* p);

/* network.c */
void tcp_callback(struct tcp_stream* stream, conn_param** param_ptr);
void conn_establish(struct tcp_stream* stream, conn_param** param_ptr);
void conn_discard(struct tcp_stream* stream, conn_param** param_ptr, char* reason);

/* message.c */
void cmsg_process(struct tcp_stream* stream, conn_param** param_ptr);
void smsg_process(struct tcp_stream* stream, conn_param** param_ptr);
packet* msg_remove(packet** begin, packet* p);
void msg_decrypt_all(conn_param* param);
void msg_dump_all(conn_param* param);
int msg_correct_size(packet* p);
packet* packet_append(packet** sequence);
