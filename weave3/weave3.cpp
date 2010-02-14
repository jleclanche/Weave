#include <map>
#include <iostream>
#include <fstream>
#include <string.h>
#include <getopt.h>

#include <pcap.h>

#include <stdio.h>
#include <ctype.h>

#include <ctime>
#include <cstdlib>
#include <typeinfo>

#include "weave.h"

void hexdump(const unsigned char *data, int size)
{
	/* dumps size bytes of *data to stdout. Looks like:
	 * [0000] 75 6E 6B 6E 6F 77 6E 20
	 *                  30 FF 00 00 00 00 39 00 unknown 0.....9.
	 * (in a single line of course)
	 * from http://sws.dett.de/mini/hexdump-c/
	 */

	const unsigned char *p = data;
	unsigned char c;
	int n;
	char bytestr[4] = {0};
	char addrstr[10] = {0};
	char hexstr[ 16*3 + 5] = {0};
	char charstr[16*1 + 5] = {0};
	for(n=1;n<=size;n++) {
		if (n%16 == 1) {
			unsigned int addr = p - (unsigned char*) data;
			/* store address for this line */
			snprintf(addrstr, sizeof(addrstr), "%.4x", addr);
		}

		c = *p;
		if (isalnum(c) == 0) {
			c = '.';
		}

		/* store hex str (for left side) */
		snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
		strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

		/* store char str (for right side) */
		snprintf(bytestr, sizeof(bytestr), "%c", c);
		strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

		if(n%16 == 0) { 
			/* line completed */
			printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
			hexstr[0] = 0;
			charstr[0] = 0;
		} else if(n%8 == 0) {
			/* half line: add whitespaces */
			strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
			strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
		}
		p++; /* next byte */
	}

	if (strlen(hexstr) > 0) {
		/* print rest of buffer if not empty */
		printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
	}
}


void handle_device_option(const char* argument)
{
	pcap_if* pc_all_devices;
	
	char pc_error[PCAP_ERRBUF_SIZE];

	if(pcap_findalldevs(&pc_all_devices, pc_error) < 0)
	{
		fprintf(stderr, "Could not obtain a list of capture devices: %s\n", pc_error);
		exit(-1);
	}
	
	pcap_if* pc_device = pc_all_devices;

	if(argument == NULL || !strcmp("list", argument))
	{
		printf("Available capture devices:\n");

		int pc_device_index = 0;
		while(pc_device != NULL)
		{
			printf("\t[% 2d] %s\n\t\t%s\n", ++pc_device_index, pc_device->name, pc_device->description);
			pc_device = pc_device->next;
		}

		exit(0);
	} else {
		int pc_selected_device_index = atoi(argument);
		if(pc_selected_device_index > 0)
		{
			int pc_device_index = 0;
			while(pc_device != NULL)
			{
				if(++pc_device_index == pc_selected_device_index)
				{
					if(!Weave::Sniffer::set_capture_device(pc_device->name))
					{
						std::cerr << "Unable to set capture device" << std::endl;
						exit(-1);
					}
					
					break;
				}

				pc_device = pc_device->next;
			}
		} else {
			if(!Weave::Sniffer::set_capture_device(argument))
			{
				std::cerr << "Unable to set capture device" << std::endl;
				exit(-1);
			}
		}
	}

	pcap_freealldevs(pc_all_devices);
}

void handle_file_option(const char* argument)
{
	if(!Weave::Sniffer::set_capture_file(argument))
	{
		std::cerr << "Unable to set capture file" << std::endl;
		exit(-1);
	}
}

typedef std::map<const Weave::GameConnection*, std::ofstream*> LogMap;
LogMap log_files;

std::ofstream* create_log(const Weave::GameConnection& conn)
{
	const char* account = conn.accountID();
	if(!account)
		return NULL;

	char fn_buffer[256 + 32];
	int account_size;
	
	strncpy(fn_buffer, account, 256);
	account_size = strlen(account);
	if(account_size > 256)
		account_size = 256;
	
	time_t fn_time = time(NULL);
	strftime(fn_buffer+account_size, 32, "_%Y-%m-%d_%H-%M-%S.wlog", gmtime(&fn_time));
	
	std::ofstream* stream = new std::ofstream(fn_buffer, std::ios_base::trunc | std::ios_base::binary);
	log_files.insert(std::make_pair(&conn, stream));
	
	account = conn.accountID();

	Weave::Log::write_header(*stream);
	
	Weave::Log::SessionInfo si = {
		/* game */			"WoW",
		/* major */ 		0,
		/* minor */ 		0,
		/* revision */ 		0,
		/* build */ 		{
			conn.build() & 0xFF,
			(conn.build() >> 8) & 0xFF
		},
		/* locale */ 		{ 0x00 },
		/* client_ip */ 	{
			conn.client().address() & 0xFF,
			(conn.client().address() >> 8) & 0xFF,
			(conn.client().address() >> 16) & 0xFF,
			(conn.client().address() >> 24) & 0xFF,
		},
		/* client_port */ 	{
			conn.client().port() & 0xFF,
			(conn.client().port() >> 8) & 0xFF,
		},
		/* server_ip */ 	{
			conn.server().address() & 0xFF,
			(conn.server().address() >> 8) & 0xFF,
			(conn.server().address() >> 16) & 0xFF,
			(conn.server().address() >> 24) & 0xFF,
		},
		/* server_port */ 	{
			conn.server().port() & 0xFF,
			(conn.server().port() >> 8) & 0xFF,
		}
	};
	
	Weave::Log::write_entry_header(*stream, Weave::Log::TC_SESSION_INFO, sizeof(si) + account_size + 1);
	stream->write((char*)(&si), sizeof(si));
	stream->write(account, account_size);
	stream->put(0);
	
	stream->flush();
	
	return stream;
}

void message_callback(const Weave::GameConnection& conn, const Weave::GameConnection::Peer& peer, const Weave::GameConnection::Peer::Header& header, const unsigned char* payload)
{
	LogMap::iterator iter = log_files.find(&conn);
	std::ofstream* stream = NULL;
	
	if(iter == log_files.end())
		stream = create_log(conn);
	else
		stream = iter->second;
	
	const char* direction;
	const char* opcode_name = Weave::Opcodes::to_string(header.opcode());
	
	Weave::Log::TypeCode entry_type;
	
	if(typeid(peer) == typeid(Weave::GameConnection::Client)) {
		direction = "<<<";
		entry_type = Weave::Log::TC_CLIENT_MESSAGE;
	} else if(typeid(peer) == typeid(Weave::GameConnection::Server)) {
		direction = ">>>";
		entry_type = Weave::Log::TC_SERVER_MESSAGE;
	} else
		return;
	
	if(stream)
	{
		Weave::Log::Message msg = {
			/* opcode */ {
				header.opcode() & 0xFF,
				(header.opcode() >> 8) & 0xFF,
				(header.opcode() >> 16) & 0xFF,
				(header.opcode() >> 24) & 0xFF,
			},
			/* client_ip */ 	{
				conn.client().address() & 0xFF,
				(conn.client().address() >> 8) & 0xFF,
				(conn.client().address() >> 16) & 0xFF,
				(conn.client().address() >> 24) & 0xFF,
			},
			/* client_port */ 	{
				conn.client().port() & 0xFF,
				(conn.client().port() >> 8) & 0xFF,
			},
			/* server_ip */ 	{
				conn.server().address() & 0xFF,
				(conn.server().address() >> 8) & 0xFF,
				(conn.server().address() >> 16) & 0xFF,
				(conn.server().address() >> 24) & 0xFF,
			},
			/* server_port */ 	{
				conn.server().port() & 0xFF,
				(conn.server().port() >> 8) & 0xFF,
			}
		};
		
		Weave::Log::write_entry_header(*stream, entry_type, sizeof(msg) + header.payloadSize());
		stream->write((char*)(&msg), sizeof(msg));
		stream->write((char*)payload, header.payloadSize());
		
		stream->flush();
	}
	
	std::cout << direction << " ";
	
	if(opcode_name)
		std::cout << opcode_name;
	else {
		std::cout << "UMSG_UNKNOWN_" << header.opcode();
	}
	
	if(header.payloadSize())
	{
		std::cout << " [" << header.payloadSize() << " byte" << (header.payloadSize() == 1 ? "" : "s") << "]" << std::endl;
		hexdump(payload, header.payloadSize());
	} else {
		std::cout << std::endl;
	}
}

int enable_log = 0;

int main(int argc, char* argv[])
{
	int option_c;

	for(;;)
	{
		static struct option option_list[] =
		{
			{"device", optional_argument, 0, 'd'},
			{"file", required_argument, 0, 'f'},
			{"log", no_argument, &enable_log, 1},
			{0, 0, 0, 0}
		};

		int option_index = 0;
		option_c = getopt_long(argc, argv, "d:f:l", option_list, &option_index);

		if(option_c == -1)
			break;

		switch(option_c)
		{
		case 0:
		case '?':
			break;
		case 'd':
			handle_device_option(optarg);
			break;
		case 'f':
			handle_file_option(optarg);
			break;
		case 'l':
			enable_log = 1;
			break;
		default:
			abort();
		}
	}
	
	Weave::GameConnection::message_callback = message_callback;

	Weave::Sniffer::run();
	
	return 0;
}
