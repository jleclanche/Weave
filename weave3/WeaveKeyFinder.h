#ifndef WEAVE_KEYFINDER_H
#define WEAVE_KEYFINDER_H

#include "WeaveGameConnection.h"
#include "WeaveCrypt.h"

namespace Weave {
	
	class KeyFinder {
	public:
		virtual bool findKey(const GameConnection::Peer& peer, const GameConnection::Peer::Header& header, size_t messageSize, unsigned char** output);
		bool isValidKey(const GameConnection::Peer& peer, const GameConnection::Peer::Header& header, size_t messageSize, const unsigned char* key, unsigned long opcodeMask = 0, unsigned long opcodeValue = 0);
	
		static bool tryAll(const GameConnection::Peer& peer, const GameConnection::Peer::Header& header, size_t messageSize, unsigned char** output);
	};
	
	class MemoryKeyFinder : public KeyFinder {
	protected:
		static const unsigned int keyOffset = 0x504;
		static const int keySearchRangeMin = -0xFFFF;
		static const int keySearchRangeMax =  0xFFFF;
	};

}

#endif /* WEAVE_KEYFINDER_H */
