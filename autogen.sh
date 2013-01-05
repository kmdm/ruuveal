#!/bin/bash
if [ "$1" == "clean" ]; then
    rm -f Makefile Makefile.in configure aclocal.m4 config.log config.status
    rm -f missing depcomp install-sh  config.guess config.sub ltmain.sh
    rm -f libtool
    rm -rf autom4te.cache .deps

    find m4/ -lname \* -exec rm -f {} \;
else
    autoreconf -fsi
fi

