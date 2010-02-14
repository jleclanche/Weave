lib_LIBRARIES = libweave.a
libweave_a_SOURCES = \
	WeaveBNetConnection.cpp \
	WeaveBNetConnection.h \
	WeaveConnection.cpp \
	WeaveConnection.h \
	WeaveCrypt.cpp \
	WeaveCrypt.h \
	WeaveGameConnection.cpp \
	WeaveGameConnection.h \
	WeaveKeyFinder.cpp \
	WeaveKeyFinder.h \
	WeaveLog.h \
	WeaveLog.cpp \
	WeaveOpcodes.cpp \
	WeaveOpcodes.h \
	WeavePtraceKeyFinder.cpp \
	WeavePtraceKeyFinder.h \
	WeaveSniffer.cpp \
	WeaveSniffer.h \
	WeaveWin32KeyFinder.cpp \
	WeaveWin32KeyFinder.h \
	weave.h

libweave_a_CXXFLAGS=-fPIC

bin_PROGRAMS = weave3

weave3_SOURCES = weave3.cpp
weave3_LDADD = libweave.a

EXTRA_DIST = \
	pyweave/setup.py \
	pyweave/weavemodule.cpp
