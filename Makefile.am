ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -D_FORTIFY_SOURCE=0 $(LIBMCRYPT_CFLAGS)
AM_LDFLAGS =  $(EXTRA_LDFLAGS) $(LIBMCRYPT_LDFLAGS)
bin_PROGRAMS = ruuveal
ruuveal_SOURCES = main.c htcaes.c htckey.c htclargezip.c htczip.c htc/devices.c
ruuveal_LDADD = $(LIBMCRYPT_LIBS)
EXTRA_DIST = *.h htc/*.h htc/*.c
