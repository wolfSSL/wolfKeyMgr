#!/bin/sh
#
# Create configure and makefile stuff...
#

# fix config/config.rpath missing bug
if test -d .git; then
    if ! test -d config/config.rpath; then
        if ! test -d config; then
            mkdir config
        fi
        touch config/config.rpath
    fi
fi

autoreconf --install --force --verbose
