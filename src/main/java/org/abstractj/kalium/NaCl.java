/*
 * Copyright 2013 Bruno Oliveira, and individual contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.abstractj.kalium;

import jnr.ffi.LibraryLoader;
import jnr.ffi.provider.FFIProvider;

public class NaCl {

    public static final Sodium SODIUM_INSTANCE;
    private static final String LIBRARY_NAME = "sodium";

    private NaCl() {
    }

    public interface Sodium {

        public String sodium_version_string();

        public static final int SHA256BYTES = 32;

        public int crypto_hash_sha256_ref(byte[] buffer, String message, long sizeof);

        public static final int SHA512BYTES = 64;

        public int crypto_hash_sha512_ref(byte[] buffer, String message, long sizeof);

        public static final int PUBLICKEY_BYTES = 32;
        public static final int SECRETKEY_BYTES = 32;

        public int crypto_box_curve25519xsalsa20poly1305_ref_keypair(byte[] publicKey, byte[] secretKey);


        public static final int NONCE_BYTES = 24;
        public static final int ZERO_BYTES = 32;
        public static final int BOXZERO_BYTES = 16;

        public void randombytes(byte[] buffer, long size);

        public int crypto_box_curve25519xsalsa20poly1305_ref(byte[] ct, byte[] msg, int length, byte[] nonce, byte[] publicKey, byte[] privateKey);

        public int crypto_box_curve25519xsalsa20poly1305_ref_open(byte[] message, byte[] ct, int length, byte[] nonce, byte[] publicKey, byte[] privateKey);

        public static final int SCALAR_BYTES = 32;

        public int crypto_scalarmult_curve25519_ref(byte[] result, byte[] intValue, byte[] point);

        public static final int XSALSA20_POLY1305_SECRETBOX_KEYBYTES = 32;
        public static final int XSALSA20_POLY1305_SECRETBOX_NONCEBYTES = 24;

        int crypto_secretbox_xsalsa20poly1305_ref(byte[] ct, byte[] msg, int length, byte[] nonce, byte[] key);

        int crypto_secretbox_xsalsa20poly1305_ref_open(byte[] message, byte[] ct, int length, byte[] nonce, byte[] key);
    }

    static {
        LibraryLoader<Sodium> libraryLoader = FFIProvider.getSystemProvider()
                .createLibraryLoader(Sodium.class)
                .library(LIBRARY_NAME);
        SODIUM_INSTANCE = libraryLoader.load();
    }
}