#include "WeaveGameConnection.h"

#include "WeaveCrypt.h"
#include "WeaveKeyFinder.h"

#include <string.h>

#ifdef WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

namespace Weave {
	GameConnection::MessageCallback GameConnection::message_callback = NULL;
	
	GameConnection::GameConnection(tuple4* addr)
	: m_client(*this, addr->saddr, addr->source), m_server(*this, addr->daddr, addr->dest)
	{
		m_accountID = NULL;
		m_encrypted = false;
		m_build = 0;
	}

	GameConnection::~GameConnection()
	{
		if(m_accountID)
			free(m_accountID);
	}
	
	const char* GameConnection::accountID() const
	{
		return m_accountID;
	}

	GameConnection::Peer::Peer(GameConnection& conn, unsigned long address, unsigned short port)
	: connection(conn)
	{
		m_canDecrypt = false;
		m_address = address;
		m_port = port;
	}

	GameConnection::Peer::Header* GameConnection::Peer::Header::copy() const
	{
		return NULL;
	}

	const unsigned char* GameConnection::Peer::key() const
	{
		return NULL;
	}

	size_t GameConnection::Peer::Header::effectiveSize() const
	{
		return 0;
	}

	size_t GameConnection::Peer::Header::payloadSize() const
	{
		return 0;
	}

	Opcodes::Opcode GameConnection::Peer::Header::opcode() const
	{
		return (Opcodes::Opcode)0;
	}

	void GameConnection::Peer::Header::decrypt(RC4_KEY* rc4_key)
	{
	}

	void GameConnection::Peer::cryptInit(const unsigned char* session_key)
	{
		m_canDecrypt = true;
		Crypt::init(&rc4_key, session_key, key());
	}

	void GameConnection::handleMessage(Peer& sender, const GameConnection::Peer::Header& header, const unsigned char* payload)
	{
		/*MessageCallbackList::iterator iter;
		for(iter = message_callbacks.begin(); iter != message_callbacks.end(); iter++)
		{
			//*iter(*this, sender, header, payload);
			MessageCallback cb = *iter;
			cb(*this, sender, header, payload);
		}
		*/
		if(message_callback) {
			(*message_callback)(*this, sender, header, payload);
		}
	}

	void GameConnection::Peer::handleMessage(const GameConnection::Peer::Header& header, const unsigned char* payload)
	{
	}

	void GameConnection::Client::handleMessage(const GameConnection::Client::Header& header, const unsigned char* payload)
	{
		if(header.opcode() == Opcodes::CMSG_AUTH_SESSION)
		{
			const char* account_id = (char*)(payload + 8);
			connection.m_accountID = strdup((char*)account_id);
			connection.m_build = (payload[0] | payload[1] << 8);

			connection.cryptInit();
		}
		
		connection.handleMessage(*this, header, payload);
	}

	void GameConnection::Server::handleMessage(const GameConnection::Server::Header& header, const unsigned char* payload)
	{
		connection.handleMessage(*this, header, payload);
	}

	GameConnection::Client::Client(GameConnection& conn, unsigned long addr, unsigned short port)
	: GameConnection::Peer(conn, addr, port)
	{
		triedFindKey = false;
	}

	GameConnection::Server::Server(GameConnection& conn, unsigned long addr, unsigned short port)
	: GameConnection::Peer(conn, addr, port)
	{
	}

	GameConnection::Client::Header::Header(const unsigned char* data, unsigned long extra_size)
	{
		memcpy(&m_data, data, sizeof(m_data));
		m_extra_size = extra_size;
	}

	GameConnection::Client::Header::Header(const GameConnection::Client::Header& header)
	{
		memcpy(&m_data, &(header.m_data), sizeof(m_data));
		m_extra_size = header.m_extra_size;
	}

	GameConnection::Client::Header* GameConnection::Client::Header::copy() const
	{
		return new GameConnection::Client::Header(*this);
	}

	size_t GameConnection::Client::Header::effectiveSize() const
	{
		if(m_extra_size)
			return size + 1;
		else
			return size;
	}

	Opcodes::Opcode GameConnection::Client::Header::opcode() const
	{
		const uint8_t* raw_opcode = m_data.opcode;
		return (Opcodes::Opcode)(raw_opcode[0] | (raw_opcode[1] << 8) | (raw_opcode[2] << 16) | (raw_opcode[3] << 24));
	}

	size_t GameConnection::Client::Header::payloadSize() const
	{
		const uint16_t raw_payload_length = m_data.size;
		return (size_t)(ntohs(raw_payload_length)) - 4 + m_extra_size;
	}

	void GameConnection::Client::Header::decrypt(RC4_KEY* rc4_key)
	{
		RC4(rc4_key, size, (unsigned char*)&m_data, (unsigned char*)&m_data);
	}

	GameConnection::Server::Header::Header(const unsigned char* data, unsigned long extra_size)
	{
		memcpy(&m_data, data, sizeof(m_data));
		m_extra_size = extra_size;
	}

	GameConnection::Server::Header::Header(const GameConnection::Server::Header& header)
	{
		memcpy(&m_data, &(header.m_data), sizeof(m_data));
		m_extra_size = header.m_extra_size;
	}

	GameConnection::Server::Header* GameConnection::Server::Header::copy() const
	{
		return new GameConnection::Server::Header(*this);
	}

	size_t GameConnection::Server::Header::effectiveSize() const
	{
		if(m_extra_size)
			return size + 1;
		else
			return size;
	}

	void GameConnection::Server::Header::decrypt(RC4_KEY* rc4_key)
	{
		RC4(rc4_key, size, (unsigned char*)&m_data, (unsigned char*)&m_data);
	}

	Opcodes::Opcode GameConnection::Server::Header::opcode() const
	{
		const uint8_t* raw_opcode = m_data.opcode;
		return (Opcodes::Opcode)(raw_opcode[0] | (raw_opcode[1] << 8));
	}

	size_t GameConnection::Server::Header::payloadSize() const
	{
		const uint16_t raw_payload_length = m_data.size;
		return (size_t)(ntohs(raw_payload_length)) - 2 + m_extra_size;
	}

	Connection::Peer& GameConnection::client()
	{
		return m_client;
	}

	Connection::Peer& GameConnection::server()
	{
		return m_server;
	}
	
	const Connection::Peer& GameConnection::client() const
	{
		return m_client;
	}

	const Connection::Peer& GameConnection::server() const
	{
		return m_server;
	}

	const unsigned char* GameConnection::Client::key() const
	{
		return Crypt::client_key;
	}

	const unsigned char* GameConnection::Server::key() const
	{
		return Crypt::server_key;
	}

	void GameConnection::cryptInit()
	{
		m_encrypted = true;
	}

	void GameConnection::Client::findKey(const GameConnection::Client::Header& header, size_t length)
	{
		if(triedFindKey)
			return;
		triedFindKey = true;

		unsigned char* key = NULL;

		if(KeyFinder::tryAll(*this, header, length, &key))
		{
			connection.cryptInit(key);
			free(key);
		}
	}

	void GameConnection::cryptInit(const unsigned char* session_key)
	{
		m_server.cryptInit(session_key);
		m_client.cryptInit(session_key);
	}

	size_t GameConnection::Client::handleData(const unsigned char* data, size_t length)
	{
		if(length < Header::size)
			return 0;

		const unsigned char* header_start = data;
		unsigned long header_extra_size = 0;
		
		RC4_KEY temp_key;
		memcpy(&temp_key, &rc4_key, sizeof(RC4_KEY));
		
		if(connection.encrypted() && m_canDecrypt)
		{
			unsigned char first_byte;
			Crypt::peek(&rc4_key, 1, data, &first_byte);
			if(first_byte & 0x80)
			{
				header_start += 1;
				header_extra_size = (first_byte ^ 0x80) << 16;
				
				RC4(&temp_key, 1, data, &first_byte);
			}
		}
		
		Header header(header_start, header_extra_size);

		if(connection.encrypted())
		{
			if(!m_canDecrypt)
				findKey(header, length);

			if(m_canDecrypt)
			{
				header.decrypt(&temp_key);
			} else {
				return 0;
			}
		}

		size_t messageSize = header.effectiveSize() + header.payloadSize();
		if(messageSize <= length)
		{
			memcpy(&rc4_key, &temp_key, sizeof(RC4_KEY));
			const unsigned char* payload = header_start + header.size;
			handleMessage(header, payload);
			return messageSize + handleData(header_start + messageSize, length - messageSize);
		} else {
			return 0;
		}
	}

	size_t GameConnection::Server::handleData(const unsigned char* data, size_t length)
	{
		if(length < Header::size)
			return 0;

		const unsigned char* header_start = data;
		unsigned long header_extra_size = 0;
		
		RC4_KEY temp_key;
		memcpy(&temp_key, &rc4_key, sizeof(RC4_KEY));
		
		if(connection.encrypted() && m_canDecrypt)
		{
			unsigned char first_byte;
			Crypt::peek(&rc4_key, 1, data, &first_byte);
			if(first_byte & 0x80)
			{
				header_start += 1;
				header_extra_size = (first_byte ^ 0x80) << 16;
				
				RC4(&temp_key, 1, data, &first_byte);
			}
		}
		
		Header header(header_start, header_extra_size);

		if(connection.encrypted())
		{
			if(m_canDecrypt)
			{
				header.decrypt(&temp_key);
			} else {
				return 0;
			}
		}

		size_t messageSize = header.effectiveSize() + header.payloadSize();
		if(messageSize <= length)
		{
			memcpy(&rc4_key, &temp_key, sizeof(RC4_KEY));
			const unsigned char* payload = header_start + header.size;
			handleMessage(header, payload);
			return messageSize + handleData(header_start + messageSize, length - messageSize);
		} else {
			return 0;
		}
	}

	bool GameConnection::encrypted() const
	{
		return m_encrypted;
	}
	
	unsigned short GameConnection::build() const
	{
		return m_build;
	}
}
