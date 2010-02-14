#ifndef WEAVE_PTRACEKEYFINDER_H
#define WEAVE_PTRACEKEYFINDER_H

#include "WeaveKeyFinder.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

namespace Weave {

#ifdef HAVE_SYS_PTRACE_H

	#include <sys/types.h>

	class PtraceKeyFinder : public MemoryKeyFinder {
	};

	class PtraceFastKeyFinder : public PtraceKeyFinder {
	public:
		bool findKey(const GameConnection::Peer& peer, const GameConnection::Peer::Header& header, size_t messageSize, unsigned char** output);
	};

#endif /* HAVE_PTRACE */

}

#endif /* WEAVE_PTRACEKEYFINDER_H */
