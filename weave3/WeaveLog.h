#ifndef WEAVE_LOG_H
#define WEAVE_LOG_H

#include <stdint.h>
#include <iostream>
#include <iterator>

namespace Weave {
	namespace Log {
		static const char ident[] = { 'W','e','a','v','e','L','o','g' };
		static const uint32_t version = 2;
		
		typedef enum {
			TC_SESSION_INFO = 0x00,
			TC_CLIENT_MESSAGE = 0x01,
			TC_SERVER_MESSAGE = 0x02
		} TypeCode;
		
		#pragma pack(1)
		typedef struct {
			char ident[8];
			uint8_t version[4];
			char reserved[20];
		} Header;
		
		typedef struct {
			uint8_t typecode[2];
			uint8_t size[4];
		} EntryHeader;
		
		typedef struct {
			char game[4];
			uint8_t major;
			uint8_t minor;
			uint8_t revision;
			uint8_t build[2];
			char locale[4];
			uint8_t client_ip[4];
			uint8_t client_port[2];
			uint8_t server_ip[4];
			uint8_t server_port[2];
		} SessionInfo;
		
		typedef struct {
			uint8_t opcode[4];
			uint8_t client_ip[4];
			uint8_t client_port[2];
			uint8_t server_ip[4];
			uint8_t server_port[2];
		} Message;
		
		#pragma pack()
		
		void write_header(std::ostream&);
		void write_entry_header(std::ostream& stream, TypeCode typecode, size_t size);
		void write_entry(std::ostream& stream, TypeCode typecode, const char* data, size_t size);
	}
}

#endif /* WEAVE_LOG_H */
