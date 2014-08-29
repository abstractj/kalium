/**
 * Copyright 2013 Bruno Oliveira, and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.abstractj.kalium;

import jnr.ffi.LibraryLoader;
import jnr.ffi.annotations.In;
import jnr.ffi.annotations.Out;
import jnr.ffi.byref.LongLongByReference;
import jnr.ffi.types.u_int64_t;

public class NaCl {

    public static Sodium sodium() {
        return SingletonHolder.SODIUM_INSTANCE;
    }

    private static final String LIBRARY_NAME = "sodium";

    private static final class SingletonHolder {
        public static final Sodium SODIUM_INSTANCE = LibraryLoader.create(Sodium.class)
                .search("/usr/local/lib")
                .search("/opt/local/lib")
                .search("lib")
                .load(LIBRARY_NAME);
    }

    private NaCl() {
    }

    public interface Sodium {

        /**
         * This function isn't thread safe. Be sure to call it once, and before performing other operations.
         *
         * Check libsodium's documentation for more info.
         */
        public int sodium_init();

        public String sodium_version_string();

        public static final int SHA256BYTES = 32;

        public int crypto_hash_sha256(@Out byte[] buffer, @In byte[] message, @u_int64_t long sizeof);

        public static final int SHA512BYTES = 64;

        public int crypto_hash_sha512(@Out byte[] buffer, @In byte[] message, @u_int64_t long sizeof);


        public static final int BLAKE2B_OUTBYTES = 64;
        public int crypto_generichash_blake2b(@Out byte[] buffer,@u_int64_t long OutLen, @In byte[] message, @u_int64_t long messageLen,
                                              @In byte[] key,  @u_int64_t long keyLen);

        public static final int PUBLICKEY_BYTES = 32;
        public static final int SECRETKEY_BYTES = 32;

        public int crypto_box_curve25519xsalsa20poly1305_keypair(@Out byte[] publicKey, @Out byte[] secretKey);


        public static final int NONCE_BYTES = 24;
        public static final int ZERO_BYTES = 32;
        public static final int BOXZERO_BYTES = 16;

        public void randombytes(@Out byte[] buffer, @u_int64_t long size);

        public int crypto_box_curve25519xsalsa20poly1305(@Out byte[] ct, @In byte[] msg, @u_int64_t long length, @In byte[] nonce,
                                                         @In byte[] publicKey, @In byte[] privateKey);

        public int crypto_box_curve25519xsalsa20poly1305_open(@Out byte[] message, @In byte[] ct, @u_int64_t long length,
                                                              @In byte[] nonce, @In byte[] publicKey, @In byte[] privateKey);

        public static final int SCALAR_BYTES = 32;

        public int crypto_scalarmult_curve25519(@Out byte[] result, @In byte[] intValue, @In byte[] point);

        public static final int XSALSA20_POLY1305_SECRETBOX_KEYBYTES = 32;
        public static final int XSALSA20_POLY1305_SECRETBOX_NONCEBYTES = 24;

        int crypto_secretbox_xsalsa20poly1305(@Out byte[] ct, @In byte[] msg, @u_int64_t long length, @In byte[] nonce, @In byte[] key);

        int crypto_secretbox_xsalsa20poly1305_open(@Out byte[] message, @In byte[] ct, @u_int64_t long length, @In byte[] nonce, @In byte[] key);

        public static final int SIGNATURE_BYTES = 64;

        int crypto_sign_ed25519_seed_keypair(@Out byte[] publicKey, @Out byte[] secretKey, @In byte[] seed);

        int crypto_sign_ed25519(@Out byte[] buffer, @Out LongLongByReference bufferLen, @In byte[] message, @u_int64_t long length, @In byte[] secretKey);

        int crypto_sign_ed25519_open(@Out byte[] buffer, @Out LongLongByReference bufferLen, @In byte[] sigAndMsg, @u_int64_t long length, @In byte[] key);
    }

    /**
     * This function isn't thread safe. Be sure to call it once, and before performing other operations.
     *
     * Check libsodium's <i>sodium_init()</i> documentation for more info.
     */
    public static int init() {
        return sodium().sodium_init();
    }
}
