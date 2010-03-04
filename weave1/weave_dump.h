/** \file File structures for binary dumps to files */

#ifdef HAVE_INTTYPES_H
#	include <inttypes.h>
#else
#	ifdef HAVE_SYS_TYPES_H
#		include <sys/types.h>
#	endif
#endif

static const char* weave_dump_header_ident = "WeaveDmp";
static const int weave_dump_version = 4;

enum weave_message_type {
	PS_MSG_CLIENT = 0,
	PS_MSG_SERVER = 1
};

typedef struct {
	char			ident[8];		/*< 8-byte unterminated string "WeaveDmp" */
	uint16_t 		dump_version;	/*< 2-byte integer indicating the version of
									    the dump file format */
	char			reserved[22];	/*< 22 bytes reserved for future use */
} weave_dump_header;				/*< 32 bytes in total */

#pragma pack(1)
typedef struct {
	uint32_t		size;			/*< 4-byte size of this header + packet
									    (corresponds to offset until next pkt)*/
	uint8_t			type;			/*< 1-byte indicating the type of the
									    packet (0 = client, 1 = server)
									    Other values reserved for future use and
									    MUST be ignored by any program not aware
									    of their meaning. */
	char			reserved1;		/*< 1-byte reserved field for future use and
									    to make it align better */
	
	uint16_t		client_build;	/*< 2-byte client game build number */
	uint32_t		client_addr;	/*< 4-byte IPv4 address for client */
	uint16_t		client_port;	/*< 2-byte TCP port for client */
	
	uint32_t		server_addr;	/*< 4-byte IPv4 address for server */
	uint16_t		server_port;	/*< 2-byte TCP port for server */
	
	struct {
	uint32_t		tv_sec;
	uint32_t		tv_usec;
	}				time;			/*< 8-byte time at which the packet was
									    captured */
	uint32_t		opcode;			/*< 4-byte opcode (note that unlike the real
									    messages, this has been normalized to
									    always be a 4-byte integer) */
	char			reserved2[16];	/*< 16 bytes reserved for future use */
} weave_message_header;				/*< 48 bytes in total */
