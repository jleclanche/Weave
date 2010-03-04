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
 * Interface to libnids.
 */

#include "weave.h"

/** Callback function for TCP/IP packets.
 *
 *  Called by NIDS whenever a new packet or a new connection have been captured.
 */
void tcp_callback(struct tcp_stream* stream, conn_param** param_ptr)
{
	/* WoW servers all use the port 3724, we can filter out everything else. */
	if(stream->addr.dest != 3724)
		return;

	if(stream->nids_state == NIDS_JUST_EST)
	{
		/* This is called when NIDS has captured a connection that has just
		   been established. We use this opportunity to allocate memory for
		   our data structure and to notify NIDS that we're interested in this
		   connection's data. */
		return conn_establish(stream, param_ptr);
	}

	if(stream->nids_state == NIDS_DATA)
	{
		/* Called whenever data is transmitted on this connection, which is then
		   dispatched to the appropriate functions. */

		if(stream->server.count_new)		/* New data for the server (CMSG) */
			cmsg_process(stream, param_ptr);
		if(stream->client.count_new)		/* New data for the client (SMSG) */
			smsg_process(stream, param_ptr);

		if(stream->server.count_new_urg)
			wlog(3, "Urgent data from client: 0x%02X\n", stream->server.urgdata);
		if(stream->client.count_new_urg)
			wlog(3, "Urgent data from server: 0x%02X\n", stream->client.urgdata);
	}

	switch(stream->nids_state)
	{
		/* There are several cases which can cause a connection to terminate.
		   We need to take care of them and clean up after ourselves. */
		case NIDS_CLOSE:
		case NIDS_RESET:
		case NIDS_TIMED_OUT:
		case NIDS_EXITING:

		return conn_discard(stream, param_ptr, "Connection closing");
	}
}

/** Prepares to sniff on a connection. */
void conn_establish(struct tcp_stream* stream, conn_param** param_ptr)
{
	char saddr[16], daddr[16];
	inet_ntop(AF_INET, &stream->addr.saddr, saddr, 16);
	inet_ntop(AF_INET, &stream->addr.daddr, daddr, 16);

	wlog(3, "New Connection: Source %s:%d → Destination %s:%d\n", saddr, stream->addr.source, daddr, stream->addr.dest);

	/** Notifies NIDS that we would like to receive data for this connection. */
	stream->client.collect = 1;
	stream->server.collect = 1;

	stream->client.collect_urg = 1;
	stream->server.collect_urg = 1;

	/** Allocates memory for the conn_param structure that holds our parameters
	 * for this \a stream. This memory will be freed in conn_discard() once the 
	 * connection has been closed or NIDS exits. */
	conn_param* param = calloc(1, sizeof(conn_param));
	assert(param != NULL);
	*param_ptr = param;

	/* Initializes the default parameters for this connection */
	param->type = CT_UNKNOWN;
	param->encrypted = 0;
	param->have_key = 0;

	param->server.cbc_iv = param->client.cbc_iv = 0;
	param->server.key_offset = param->client.key_offset = 0;
	param->server.packet_sequence = param->client.packet_sequence = NULL;

	param->client.ip = stream->addr.saddr;
	param->server.ip = stream->addr.daddr;
	param->client.port = stream->addr.source;
	param->server.port = stream->addr.dest;
}

/** Stops watching a connection. */
void conn_discard(struct tcp_stream* stream, conn_param** param_ptr, char* reason)
{
	if(*param_ptr == NULL)
		return;
	
	const char* ct_strings[] = { "unknown", "auth", "game" };
	int ct = (*param_ptr)->type;
	
	if(ct < 0 || ct > sizeof(ct_strings))
	{
		wlog(2, "\nWarning: Corrupt connection type (%d)\n", ct);
		ct = 0;
	}
	
	if(reason)
		wlog(2, "\nDiscarding %s connection (%s)\n", ct_strings[ct], reason);
	else
		wlog(2, "\nDiscarding %s connection\n", ct_strings[ct]);

	/** Stops sniffing on a connection by telling NIDS that we're no longer
	   interested in its traffic. */
	stream->client.collect = 0;
	stream->server.collect = 0;

	if((*param_ptr)->account != NULL)
		free((*param_ptr)->account);
	
	if((*param_ptr)->log_to)
		fclose((*param_ptr)->log_to);
	
	/** Frees the memory that we used to store the connection parameters. */
	free(*param_ptr);
	
	*param_ptr = NULL;
}
