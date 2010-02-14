#ifndef WEAVE_GAMECONNECTION_H
#define WEAVE_GAMECONNECTION_H

#include <stdio.h>
#include <stdint.h>

#include <nids.h>

#include "WeaveCrypt.h"
#include "WeaveOpcodes.h"
#include "WeaveConnection.h"

namespace Weave {
	class GameConnection : public Connection {
	public:
		GameConnection(tuple4* addr);
		~GameConnection();
	
		static const unsigned short port = 3724;

		const char* accountID(void) const;
	
		class Peer : public Connection::Peer {
		public:
			class Header {
			public:
				virtual Header* copy() const;

				virtual size_t effectiveSize() const;
				virtual size_t payloadSize() const;
				virtual Opcodes::Opcode opcode() const;
				
				virtual void decrypt(RC4_KEY* rc4_key);
			protected:
				unsigned long m_extra_size;
			};

			friend class GameConnection;

			virtual const unsigned char* key() const;

			GameConnection& connection;

		protected:
			Peer(GameConnection&, unsigned long address, unsigned short port);

			virtual void handleMessage(const Header& header, const unsigned char* payload);
			void cryptInit(const unsigned char* session_key);

			RC4_KEY rc4_key;

			bool m_canDecrypt;
		};
		
		typedef void (*MessageCallback)(const GameConnection&, const Peer&, const Peer::Header&, const unsigned char*);
		static MessageCallback message_callback;

		class Client : public Peer {
		public:
			Client(GameConnection&, unsigned long address, unsigned short port);

			class Header : public Peer::Header {
			public:
				Header(const Header& header);
				Header(const unsigned char* data, unsigned long extra_size);
				Header* copy() const;

				static const size_t size = 6;
				
				size_t effectiveSize() const;
				size_t payloadSize() const;
				Opcodes::Opcode opcode() const;
			
				void decrypt(RC4_KEY* rc4_key);
			private:
				struct {
					uint16_t size;
					uint8_t opcode[4];
				} m_data;
			};

			const unsigned char* key() const;
			void handleMessage(const Header& header, const unsigned char* payload);

			size_t handleData(const unsigned char* data, size_t length);

		protected:
			void findKey(const Header& header, size_t length);
			bool triedFindKey;
		};

		friend class Client;
		Connection::Peer& client();
		const Connection::Peer& client() const;

		class Server : public Peer {
		public:
			Server(GameConnection&, unsigned long address, unsigned short port);

			class Header : public Peer::Header {
			public:
				Header(const Header& header);
				Header(const unsigned char* data, unsigned long extra_size);
				Header* copy() const;

				static const size_t size = 4;
				
				size_t effectiveSize() const;
				size_t payloadSize() const;
				Opcodes::Opcode opcode() const;

				void decrypt(RC4_KEY* rc4_key);
			private:
				struct {
					uint16_t size;
					uint8_t opcode[2];
				} m_data;
			};

			const unsigned char* key() const;
			void handleMessage(const Header& header, const unsigned char* payload);
			size_t handleData(const unsigned char* data, size_t length);

		protected:
			
		};

		friend class Server;
		Connection::Peer& server();
		const Connection::Peer& server() const;

		void handleMessage(Peer& sender, const Peer::Header& header, const unsigned char* payload);

		bool encrypted() const;

		void cryptInit();
		void cryptInit(const unsigned char* session_key);
		
		unsigned short build() const;
	private:
		char* m_accountID;
		unsigned short m_build;
		bool m_encrypted;

		Client m_client;
		Server m_server;
	};

}

#endif /* WEAVE_GAMECONNECTION_H */
