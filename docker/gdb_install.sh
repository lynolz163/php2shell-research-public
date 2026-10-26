#!/bin/sh
# EOL-debian-tolerant gdb/procps bootstrap for the version matrix.
which gdb >/dev/null 2>&1 && { echo gdb; exit 0; }
# Official *-alpine images use musl and have no apt database.  Keep the
# debugger bootstrap bounded and explicit for the musl dimension.
if command -v apk >/dev/null 2>&1; then
    apk add --no-cache gdb procps coreutils >/dev/null 2>&1 && { echo gdb; exit 0; }
fi
APT_NET="-o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20"
if apt-get $APT_NET update -qq >/dev/null 2>&1 && \
   apt-get $APT_NET install -y -qq gdb procps >/dev/null 2>&1; then
    echo gdb; exit 0
fi
# EOL debian (bullseye and older): repos moved to archive.debian.org and
# Release files are expired -> point at the archive and skip validity check.
sed -i -E 's|https?://deb\.debian\.org|http://archive.debian.org|g;
           s|https?://security\.debian\.org|http://archive.debian.org|g' \
    /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null
sed -i -E '/(updates|security|backports)/d' \
    /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null
apt-get $APT_NET -o Acquire::Check-Valid-Until=false update -qq 2>/dev/null
apt-get $APT_NET -o Acquire::Check-Valid-Until=false install -y -qq gdb procps \
    >/dev/null 2>&1 && echo gdb
