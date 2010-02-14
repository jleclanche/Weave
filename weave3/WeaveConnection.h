#ifndef WEAVE_CONNECTION_H
#define WEAVE_CONNECTION_H

#include <stdlib.h>

namespace Weave {

	class Connection {
	public:
		virtual ~Connection();
	
		class Peer {
		public:
			virtual size_t handleData(const unsigned char* data, size_t length);
			unsigned long address() const;
			unsigned short port() const;
		
			bool operator<(const Peer& other) const;
		protected:
			unsigned long m_address;
			unsigned short m_port;
		};

		virtual Peer& client();
		virtual Peer& server();
		
		virtual const Peer& client() const;
		virtual const Peer& server() const;

		bool operator<(const Connection& other) const;
	protected:
		Peer m_client;
		Peer m_server;
	};

}

#endif /* WEAVE_CONNECTION_H */
