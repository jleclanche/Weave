#include "WeaveConnection.h"

#include <malloc.h>
namespace Weave {
	Connection::~Connection()
	{
	}
	
	size_t Connection::Peer::handleData(const unsigned char* data, size_t length)
	{
		return length;
	}

	Connection::Peer& Connection::client()
	{
		return m_client;
	}

	Connection::Peer& Connection::server()
	{
		return m_server;
	}
	
	const Connection::Peer& Connection::client() const
	{
		return m_client;
	}

	const Connection::Peer& Connection::server() const
	{
		return m_server;
	}
	
	unsigned long Connection::Peer::address() const
	{
		return m_address;
	}
	
	unsigned short Connection::Peer::port() const
	{
		return m_port;
	}
	
	bool Connection::Peer::operator<(const Peer& other) const
	{
		return (m_address < other.m_address) && (m_port < other.m_port);
	}
	
	bool Connection::operator<(const Connection& other) const
	{
		return (client() < other.client()) && (server() < other.server());
	}
}
