dnl ------------------------------------------------------------------

AC_INIT(pftabled, 1.09)
AC_PREREQ(2.62)

dnl AC_REVISION([$Revision$])

AC_CONFIG_HEADERS(config.h)

dnl ------------------------------------------------------------------
dnl Check for programs
dnl ------------------------------------------------------------------

AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_CHECK_PROG(NROFF, [mandoc], [mandoc -Tascii -mandoc])
AC_CHECK_PROG(NROFF, [nroff], [nroff -Tascii -man])
AC_CACHE_SAVE

dnl ------------------------------------------------------------------
dnl Check for headers
dnl ------------------------------------------------------------------

AC_C_CONST
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS(stdint.h sys/types.h inttypes.h)
AC_CHECK_HEADERS(sys/socket.h netinet/in.h arpa/inet.h)
AC_CHECK_HEADERS(errno.h netdb.h)
AC_CACHE_SAVE

dnl ------------------------------------------------------------------
dnl Check for platform and select build targets
dnl ------------------------------------------------------------------

AC_CHECK_FILE(/usr/include/net/pfvar.h,
[
	ALLTARGET="client server"
	INSTALLTARGET="client-install server-install"
	AC_MSG_RESULT([building on pf platform: client and server])
],[
	ALLTARGET="client"
	INSTALLTARGET="client-install"
	AC_MSG_RESULT([building on non-pf platform: only client])
])
AC_SUBST(ALLTARGET)
AC_SUBST(INSTALLTARGET)

dnl ------------------------------------------------------------------
dnl Check for functions
dnl ------------------------------------------------------------------

AC_CHECK_FUNCS(gethostbyname, , [AC_CHECK_LIB(nsl, gethostbyname)])
AC_CHECK_FUNCS(socket, , [AC_CHECK_LIB(socket, socket)])
AC_CHECK_FUNCS(inet_pton, , [AC_CHECK_LIB(resolv, inet_pton)])

dnl ------------------------------------------------------------------
dnl Generate Makefile by default. Others only if their .in file
dnl exists in the current directory, which happens in my workdir
dnl but not for distributed tarballs.
dnl ------------------------------------------------------------------

AC_CONFIG_FILES(Makefile)
if test -r "README.in"; then
	AC_CONFIG_FILES(README)
fi

AC_OUTPUT()

AC_MSG_RESULT()
AC_MSG_RESULT([Configured successfully. Now run make.])
AC_MSG_RESULT()

