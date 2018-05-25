#!/bin/bash

. scripts/version.sh

wget -c https://download.libsodium.org/libsodium/releases/$LIBSODIUM
tar xzvf $LIBSODIUM
cd libsodium-stable && mkdir vendor
./configure --prefix=`pwd`/vendor
make && make install
cd ../
