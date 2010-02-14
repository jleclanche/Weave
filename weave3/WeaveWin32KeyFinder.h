#ifndef WEAVE_WIN32KEYFINDER_H
#define WEAVE_WIN32KEYFINDER_H

#include "WeaveKeyFinder.h"

namespace Weave {

#ifdef WIN32

	#include <tchar.h>
	#include <windows.h>
	
	class Win32KeyFinder : public MemoryKeyFinder {
	};

	class Win32FastKeyFinder : public Win32KeyFinder {
	public:
		bool findKey(const GameConnection::Peer& peer, const GameConnection::Peer::Header& header, size_t messageSize, unsigned char** output);
	};

	class Win32ExhaustiveKeyFinder : public Win32KeyFinder {
	public:
		bool findKey(const GameConnection::Peer& peer, const GameConnection::Peer::Header& header, size_t messageSize, unsigned char** output);
	};

#endif /* WIN32 */

}

#endif /* WEAVE_WIN32KEYFINDER_H */
