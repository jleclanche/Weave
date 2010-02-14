#include "WeaveSniffer.h"

#include "WeaveConnection.h"
#include "WeaveBNetConnection.h"
#include "WeaveGameConnection.h"

#include <string.h>
#include <nids/nids.h>

namespace Weave {
	namespace Sniffer {
		
		void tcp_callback(struct tcp_stream* stream, void** param)
		{
			Connection* connection = (Connection*)(*param);

			if(stream->nids_state == NIDS_JUST_EST)
			{
				connection = NULL;

				if(stream->addr.dest == BNetConnection::port)
				{
					connection = new BNetConnection(&(stream->addr));
					*param = connection;
				} else if(stream->addr.dest == GameConnection::port) {
					connection = new GameConnection(&(stream->addr));
					*param = connection;
				}

				if(connection == NULL)
					return;

				stream->client.collect = 1;
				stream->server.collect = 1;
			} else if(stream->nids_state == NIDS_DATA) {
				if(stream->client.count_new)
				{
					nids_discard(stream, connection->server().handleData((unsigned char*)stream->client.data, stream->client.count - stream->client.offset));
				} else if(stream->server.count_new)
				{
					nids_discard(stream, connection->client().handleData((unsigned char*)stream->server.data, stream->server.count - stream->server.offset));
				}
			} else if(stream->nids_state & (NIDS_CLOSE | NIDS_RESET | NIDS_EXITING)) {
				if(connection)
				{
					delete connection;
					*param = NULL;
				}
			}
		}
		
		bool initialized = false;
		bool callback_registered = false;
		
		bool initialize(void)
		{
			// Disable portscan detection
			nids_params.scan_num_hosts = 0;
			nids_params.multiproc = 1;
			
			initialized = (bool)nids_init();
			
			if(!callback_registered)
			{
				nids_register_tcp((void*)tcp_callback);
				callback_registered = true;
			}
			
			return initialized;
		}
		
		const char* capture_device(void)
		{
			return nids_params.device;
		}
		
		const char* capture_file(void)
		{
			return nids_params.filename;
		}
		
		bool set_capture_device(const char* device)
		{
			if(nids_params.filename)
				free(nids_params.filename);
			if(nids_params.device)
				free(nids_params.device);
			
			nids_params.filename = NULL;
			nids_params.device = strdup(device);
			
			return initialize();
		}
		
		bool set_capture_file(const char* filename)
		{
			if(nids_params.filename)
				free(nids_params.filename);
			if(nids_params.device)
				free(nids_params.device);
			
			nids_params.filename = strdup(filename);
			nids_params.device = NULL;
			
			return initialize();
		}
		
		bool run(void)
		{
			if(!initialized)
				initialize();
			
			return initialized && (bool)nids_run();
		}
		
		bool next(void)
		{
			if(!initialized)
				initialize();
			
			return initialized && (bool)nids_next();
		}
		
		bool dispatch(int count)
		{
			if(!initialized)
				initialize();
			
			return initialized && (bool)nids_dispatch(count);
		}
		
	}
}
