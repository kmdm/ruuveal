#!/bin/bash
# A simple test script.
RUUVEAL="../ruuveal"
TMPDIR=tmp.$$
UNZIP="unzip"

cd $(dirname $0)

[ -f ../ruuveal ] || exit 1
mkdir -p tmp.$$ || exit 1

trap "rm -rf $TMPDIR" EXIT

for x in *.zip; do
    d=$(echo $x | sed 's/\.zip//')
    echo -n "Testing $d..."
    rm -f $TMPDIR/*
    if ! $RUUVEAL --device $d $x $TMPDIR/out.zip &>/dev/null; then
        echo "failed (ruuveal)."
        continue
    fi

    cd $TMPDIR

    if ! $UNZIP out.zip &>/dev/null; then
        echo "failed (unzip)."
    else
        echo "passed."
    fi

    cd - &>/dev/null
done
