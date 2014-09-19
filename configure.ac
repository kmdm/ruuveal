AC_CONFIG_MACRO_DIR([m4])
AC_INIT([ruuveal],[0.2.0])
AM_INIT_AUTOMAKE([1.10 no-define foreign])
AC_PROG_LIBTOOL
AC_PROG_CC

AC_CHECK_LIB(crypto, AES_set_decrypt_key)
AC_CHECK_LIB(ssl, SSL_library_init)

AC_CHECK_HEADERS(getopt.h pthread.h string.h)


AC_CONFIG_FILES(Makefile)
AC_OUTPUT
