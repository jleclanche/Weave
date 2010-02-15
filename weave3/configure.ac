AC_INIT(libweave, 3.0)
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)
AC_CHECK_HEADERS([sys/ptrace.h])
AC_CHECK_HEADERS([nids.h], [], AC_MSG_ERROR(Could not find libnids headers))
AC_CHECK_HEADERS([openssl/rc4.h], [], AC_MSG_ERROR(Could not find OpenSSL headers))
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_CHECK_LIB(nids, nids_init, [], AC_MSG_ERROR(Could not link with libnids))
AC_SEARCH_LIBS([RC4], [ssl eay32], [], AC_MSG_ERROR(Could not find OpenSSL library))
AC_CONFIG_FILES([Makefile])
AC_OUTPUT