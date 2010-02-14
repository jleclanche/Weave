#ifndef WEAVE_BNETCONNECTION_H
#define WEAVE_BNETCONNECTION_H

#include <nids/nids.h>
#include "WeaveConnection.h"

namespace Weave {
		
	class BNetConnection : public Connection {
	public:
		BNetConnection(tuple4* addr);

		static const unsigned short port = 1119;
	};

}

#endif /* WEAVE_BNETCONNECTION_H */
