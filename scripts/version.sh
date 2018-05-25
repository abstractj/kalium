#!/bin/bash

export LIBSODIUM=`curl -s https://download.libsodium.org/libsodium/releases/ | sed -e 's/<[^>]*>//g' | grep -i stable | awk '{print $1}' | tail -n2 | grep -v "minisig"`
