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
 * Main application logic.
 */

#include "weave.h"
#include "weave_dump.h"

int verbosity_level = 1;
int binary_output = 0;
FILE* msg_log_to = NULL;
int nids_checksumming = 0;
int msg_enable_logging = 0;

/** Application entry point. */
int main(int argc, char* argv[])
{
	nids_params.device = "all";
	
	int getopt_c;
	
	while(1)
	{
		static struct option getopt_long_options[] =
		{
			{"nids-tcp-streams", 		required_argument, 0, 0},
			{"nids-hosts", 				required_argument, 0, 0},
			{"nids-filename", 			required_argument, 0, 0},
			{"nids-sk-buff-size", 		required_argument, 0, 0},
			{"nids-dev-addon", 			required_argument, 0, 0},
			{"nids-pcap-filter", 		required_argument, 0, 0},
			{"nids-queue-limit", 		required_argument, 0, 0},
			{"version",					no_argument,		0,	0},
			{"nids-no-promisc", 		no_argument, &(nids_params.promisc), 0},
			{"nids-multiproc", 			no_argument, &(nids_params.multiproc), 1},
			{"nids-tcp-workarounds", 	no_argument, &(nids_params.tcp_workarounds), 1},
			{"nids-checksumming",	no_argument, &(nids_checksumming), 1},
			{"binary",					no_argument,		0,	'b'},
			{"device",					required_argument,	0,	'd'},
			{"log",						no_argument,		0,	'l'},
			{"verbose",					optional_argument,	0,	'v'},
			{0,							0,					0,	0}
		};
		
		int getopt_long_index = 0;
		int optarg_i;
		
		getopt_c = getopt_long(argc, argv, "bcld:v::", getopt_long_options, &getopt_long_index);
		
		if(getopt_c == -1)
			break;
		
		switch(getopt_c)
		{
			case 0:
				if(optarg)
					optarg_i = atoi(optarg);
				switch(getopt_long_index)
				{
					case 0:
						nids_params.n_tcp_streams = optarg_i;
						break;
					case 1:
						nids_params.n_hosts = optarg_i;
						break;
					case 2:
						nids_params.filename = optarg;
						nids_params.device = NULL;
						break;
					case 3:
						nids_params.sk_buff_size = optarg_i;
						break;
					case 4:
						nids_params.dev_addon = optarg_i;
						break;
					case 5:
						nids_params.pcap_filter = optarg;
						break;
					case 6:
						nids_params.queue_limit = optarg_i;
						break;
					case 7:
						printf(PACKAGE_VERSION);
						if(isatty(fileno(stdout)))
							printf("\n");
						return 0;
				}
				break;
			
			case 'b':
				binary_output = 1;
				msg_dump_header(stdout);
				break;
			
			case 'c':
				nids_checksumming = 1;
				break;
			
			case 'd':
				nids_params.device = optarg;
				break;
			
			case 'l':
				msg_enable_logging = 1;
				
				break;
			
			case 'v':
				if(optarg)
					verbosity_level = atoi(optarg); 
				else
					verbosity_level ++;
				
				break;
			
			default:
				abort();
		};
	}
	
	wlog(1, "%s - WoW Eavesdropper and Traffic Decrypter\n\n", PACKAGE_STRING);
	wlog(2, "Setting up capture device \"%s\"\n", nids_params.device);
	
	/** Attempts to set up the capture device, displaying an error message in
	 *  case it fails.
	 */
	if(!nids_init())
	{
		wlog(0, "Initialization of libnids failed (%s)\n", nids_errbuf);
		if(getuid())
			wlog(1, "Please note that %s requires root privileges to set up the capture device.\n", PACKAGE_NAME);
		return 1;
	}
	
	/** \todo We probably should drop root privileges here. */
	
	if(!nids_checksumming)
	{
		struct nids_chksum_ctl cctl = { 0, 0, NIDS_DONT_CHKSUM };
		wlog(3, "Disabling TCP checksum validation\n");
		nids_register_chksum_ctl(&cctl, 1);
	}
	
	/** Registers a callback for each TCP/IP packet that is captured by NIDS. */
	nids_register_tcp(tcp_callback);
	
	/** Passes control to NIDS. */
	nids_run();
	
	/** In case of success, this function never returns. */
	return 0;
}

void wlog(int level, const char *format, ...)
{
	va_list arg;
	va_start(arg, format);
	if(level <= verbosity_level)
		vfprintf(stderr, format, arg);
	fflush(stderr);
	va_end(arg);
}

int msg_dump_header(FILE* stream)
{
	weave_dump_header hdr;
	memset(&hdr, 0, sizeof(hdr));
	memcpy(&hdr.ident, weave_dump_header_ident, 8);
	hdr.dump_version = weave_dump_version;

	if(fwrite(&hdr, sizeof(hdr), 1, stream) != 1)
	{
		wlog(0, "Could not write file header (%s)\n", strerror(errno));
		return errno;
	}

	/** Since NIDS handles the interrupts for us and doesn't return
	 *  control to our main function, we can't fclose() the stream,
	 *  which is why we have to flush it after every write. */
	fflush(stream);
	
	return 0;
}

/** Dumps the message to stdout in a human-readable form. */
void msg_dump(packet* p) {
	int opcode;
	int data_size;
	char* source_strings[] = { "Client", "Server" };
	char* message = p->data;
	char* data;
	const char* name;
	
	if(p->source == PS_CLIENT)
	{
		/* CMSG */
		opcode = ((cmsg_header*)message)->opcode;
		data_size = p->size - 6;
		data = message + sizeof(cmsg_header);
	} else {
		/* SMSG */
		opcode = ((smsg_header*)message)->opcode;
		data_size = p->size - 4;
		data = message + sizeof(smsg_header);
	}
	
	/* Translate the opcode to its name for display.
	   
	   Note that this normally is not Weave's job, and will be outsourced to
	   another application once binary output to a file is implemented. */
	name = opcode_name(opcode);
	if(name == NULL)
		name = (char*) "Unknown";
	
	
	weave_message_header hdr;
	memset(&hdr, 0, sizeof(hdr));

	hdr.size = sizeof(hdr) + data_size;
	hdr.type = p->source;
	hdr.client_build = ((conn_param*)p->conn)->build;
	hdr.client_addr = ((conn_param*)p->conn)->client.ip;
	hdr.client_port = ((conn_param*)p->conn)->client.port;
	hdr.server_addr = ((conn_param*)p->conn)->server.ip;
	hdr.server_port = ((conn_param*)p->conn)->server.port;

	hdr.time.tv_sec = p->time.tv_sec;
	hdr.time.tv_usec = p->time.tv_usec;

	hdr.opcode = opcode;
	
	if(binary_output)
		assert(fwrite(&hdr, sizeof(hdr), 1, stdout) == 1);
	
	FILE* log_to = ((conn_param*)p->conn)->log_to;
	
	if(log_to)
		assert(fwrite(&hdr, sizeof(hdr), 1, log_to) == 1);
	
	if(data_size)
	{
		/* There is extra data in the packet beyond the header. */
		
		if(binary_output)
		{
			assert(fwrite(data, data_size, 1, stdout) == 1);
		} else {
			printf("%s message: Opcode = 0x%X (%s) [%d data bytes]\n", source_strings[p->source], opcode, name, data_size);
			hex_dump(data, data_size);
		}
		
		if(log_to)
			assert(fwrite(data, data_size, 1, log_to) == 1);
	} else if(!binary_output) {
		printf("%s message: Opcode = 0x%X (%s)\n", source_strings[p->source], opcode, name);
	}
	
	fflush(stdout);
	if(log_to)
		fflush(log_to);
}

FILE* msg_log_create(const char* account)
{
	char fn_buffer[256 + 32];
	int account_size;
	
	if(account != NULL)
	{
		strncpy(fn_buffer, account, 256);
		account_size = strlen(account);
		if(account_size > 256)
			account_size = 256;
	} else {
		account_size = 7;
		strncpy(fn_buffer, "UNKNOWN", 7);
	}
	
	time_t fn_time = time(NULL);
	strftime(fn_buffer+account_size, 32, "_%F_%H-%M-%S.wlog", gmtime(&fn_time));
	
	wlog(2, "Creating log file \"%s\"\n", fn_buffer);
	return fopen(fn_buffer, "wb");
}

void hex_dump(void *data, int size)
{
	/* dumps size bytes of *data to stdout. Looks like:
	 * [0000] 75 6E 6B 6E 6F 77 6E 20
	 *                  30 FF 00 00 00 00 39 00 unknown 0.....9.
	 * (in a single line of course)
	 * from http://sws.dett.de/mini/hexdump-c/
	 */

	unsigned char *p = data;
	unsigned char c;
	int n;
	char bytestr[4] = {0};
	char addrstr[10] = {0};
	char hexstr[ 16*3 + 5] = {0};
	char charstr[16*1 + 5] = {0};
	for(n=1;n<=size;n++) {
		if (n%16 == 1) {
			/* modified to compile cleanly */
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
