#include "WeaveKeyFinder.h"
#include "WeaveWin32KeyFinder.h"
#include "WeavePtraceKeyFinder.h"

namespace Weave {
	#ifdef HAVE_CONFIG_H
	#include "config.h"
	#endif /* HAVE_CONFIG_H */
	
	bool KeyFinder::findKey(const GameConnection::Peer& peer, const GameConnection::Peer::Header& header, size_t messageSize, unsigned char** output)
	{
		return false;
	}

	bool KeyFinder::isValidKey(const GameConnection::Peer& peer, const GameConnection::Peer::Header& header, size_t messageSize, unsigned const char* key, unsigned long opcodeMask, unsigned long opcodeValue)
	{
		RC4_KEY try_key;
		Crypt::init(&try_key, key, peer.key());

		GameConnection::Peer::Header* try_header = header.copy();
		try_header->decrypt(&try_key);
		
		bool valid = (try_header->payloadSize() + try_header->effectiveSize() == messageSize) && ((unsigned long)try_header->opcode() & opcodeMask == opcodeValue) && ((unsigned long)try_header->opcode() < Opcodes::NUM_MSG_TYPES);

		delete try_header;

		return valid;
	}

	bool KeyFinder::tryAll(const GameConnection::Peer& peer, const GameConnection::Peer::Header& header, size_t messageSize, unsigned char** output)
	{
	#ifdef WIN32
		Win32FastKeyFinder w32fkf;
		if(w32fkf.findKey(peer, header, messageSize, output))
			return true;

		Win32ExhaustiveKeyFinder w32ekf;
		if(w32ekf.findKey(peer, header, messageSize, output))
			return true;
	#endif
	#ifdef HAVE_SYS_PTRACE_H
		PtraceFastKeyFinder pfkf;
		if(pfkf.findKey(peer, header, messageSize, output))
			return true;
	#endif
		
		return false;
	}

}
