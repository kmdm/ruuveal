AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -D_FORTIFY_SOURCE=0
AM_LDFLAGS =  $(EXTRA_LDFLAGS)
EXTRA_DIST = *.h htc/*.h htc/*.c

bin_PROGRAMS = ruuveal bruutveal
ruuveal_SOURCES = main.c htcaes.c htckey.c htclargezip.c htczip.c htc/devices.c
bruutveal_SOURCES = bruutveal.c htcaes.c htckey.c htclargezip.c htczip.c htc/devices.c
bruutveal_CFLAGS = $(AM_CFLAGS) -pthread
