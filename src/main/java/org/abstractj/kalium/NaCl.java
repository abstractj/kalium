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
        Sodium sodium = SingletonHolder.SODIUM_INSTANCE;
        checkVersion(sodium);
        return sodium;
    }

    private static final String LIBRARY_NAME = "sodium";

    private static final class SingletonHolder {
        public static final Sodium SODIUM_INSTANCE = LibraryLoader.create(Sodium.class)
                .search("/usr/local/lib")
                .search("/opt/local/lib")
                .search("lib")
                .load(LIBRARY_NAME);

    }

    public static final Integer[] MIN_SUPPORTED_VERSION = new Integer[] { 1, 0, 3 };

    private static boolean versionSupported = false;

    private static final void checkVersion(Sodium lib) {
        if (!versionSupported) {
            String[] version = lib.sodium_version_string().split("\\.");
            versionSupported = version.length >= 3 &&
                MIN_SUPPORTED_VERSION[0] <= new Integer(version[0]) &&
                MIN_SUPPORTED_VERSION[1] <= new Integer(version[1]) &&
                MIN_SUPPORTED_VERSION[2] <= new Integer(version[2]);
        }
        if (!versionSupported) {
            String message = String.format("Unsupported libsodium version: %s. Please update",
                                        lib.sodium_version_string());
            throw new UnsupportedOperationException(message);
        }
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

        // ---------------------------------------------------------------------
        // Generating Random Data

        public void randombytes(@Out byte[] buffer, @u_int64_t long size);

        // ---------------------------------------------------------------------
        // Secret-key cryptography: Authenticated encryption

        public static final int XSALSA20_POLY1305_SECRETBOX_KEYBYTES = 32;
        public static final int XSALSA20_POLY1305_SECRETBOX_NONCEBYTES = 24;

        int crypto_secretbox_xsalsa20poly1305(@Out byte[] ct, @In byte[] msg, @u_int64_t long length, @In byte[] nonce, @In byte[] key);

        int crypto_secretbox_xsalsa20poly1305_open(@Out byte[] message, @In byte[] ct, @u_int64_t long length, @In byte[] nonce, @In byte[] key);

        // ---------------------------------------------------------------------
        // Secret-key cryptography: Authentication

        public static final int HMACSHA512256_BYTES = 32;

        public static final int HMACSHA512256_KEYBYTES = 32;

        public int crypto_auth_hmacsha512256(@Out byte[] mac, @In byte[] message, @u_int64_t long sizeof, @In byte[] key);

        public int crypto_auth_hmacsha512256_verify(@In byte[] mac, @In byte[] message, @u_int64_t long sizeof, @In byte[] key);

        // ---------------------------------------------------------------------
        // Secret-key cryptography: AEAD

        // TODO

        // ---------------------------------------------------------------------
        // Public-key cryptography: Authenticated encryption

        public static final int PUBLICKEY_BYTES = 32;
        public static final int SECRETKEY_BYTES = 32;

        public int crypto_box_curve25519xsalsa20poly1305_keypair(@Out byte[] publicKey, @Out byte[] secretKey);

        public static final int NONCE_BYTES = 24;
        public static final int ZERO_BYTES = 32;
        public static final int BOXZERO_BYTES = 16;
        public static final int BEFORENMBYTES = 32;
        public static final int MAC_BYTES = ZERO_BYTES - BOXZERO_BYTES;
        public static final int SEAL_BYTES = PUBLICKEY_BYTES + MAC_BYTES;

        public int crypto_box_curve25519xsalsa20poly1305_beforenm(@Out byte[] sharedkey,
                                                                  @In byte[] publicKey, @In byte[] privateKey);

        public int crypto_box_curve25519xsalsa20poly1305(@Out byte[] ct, @In byte[] msg, @u_int64_t long length, @In byte[] nonce,
                                                         @In byte[] publicKey, @In byte[] privateKey);

        public int crypto_box_curve25519xsalsa20poly1305_afternm(@Out byte[] ct, @In byte[] msg, @u_int64_t long length, @In byte[] nonce,
                                                                 @In byte[] shared);

        public int crypto_box_curve25519xsalsa20poly1305_open(@Out byte[] message, @In byte[] ct, @u_int64_t long length,
                                                              @In byte[] nonce, @In byte[] publicKey, @In byte[] privateKey);

        public int crypto_box_curve25519xsalsa20poly1305_open_afternm(@Out byte[] message, @In byte[] ct, @u_int64_t long length,
                                                                      @In byte[] nonce, @In byte[] shared);

        // ---------------------------------------------------------------------
        // Public-key cryptography: Public-key signatures

        public static final int SIGNATURE_BYTES = 64;

        int crypto_sign_ed25519_seed_keypair(@Out byte[] publicKey, @Out byte[] secretKey, @In byte[] seed);

        int crypto_sign_ed25519(@Out byte[] buffer, @Out LongLongByReference bufferLen, @In byte[] message, @u_int64_t long length, @In byte[] secretKey);

        int crypto_sign_ed25519_open(@Out byte[] buffer, @Out LongLongByReference bufferLen, @In byte[] sigAndMsg, @u_int64_t long length, @In byte[] key);

        // ---------------------------------------------------------------------
        // Public-key cryptography: Sealed boxes

        public int crypto_box_seal(@Out byte[] ct, @In byte[] message, @In @u_int64_t int length, @In byte[] publicKey);

        public int crypto_box_seal_open(@Out byte[] message, @In byte[] c, @In @u_int64_t int length, @In byte[] publicKey, @In byte[] privateKey);

        // ---------------------------------------------------------------------
        // Hashing: Generic hashing

        public static final int BLAKE2B_OUTBYTES = 32;

        public int crypto_generichash_blake2b(@Out byte[] buffer, @u_int64_t long outLen,
                                              @In byte[] message, @u_int64_t long messageLen,
                                              @In byte[] key, @u_int64_t long keyLen);
        public int crypto_generichash_blake2b_salt_personal(@Out byte[] buffer, @u_int64_t long outLen,
                                                            @In byte[] message, @u_int64_t long messageLen,
                                                            @In byte[] key,  @u_int64_t long keyLen,
                                                            @In byte[] salt,
                                                            @In byte[] personal);

        // ---------------------------------------------------------------------
        // Hashing: Short-input hashing

        // TODO

        // ---------------------------------------------------------------------
        // Password hashing

        public static final int PWHASH_SCRYPTSALSA208SHA256_STRBYTES = 102;
        public static final int PWHASH_SCRYPTSALSA208SHA256_OUTBYTES = 64;
        public static final int PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE = 524288;
        public static final int PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE = 16777216;

        public int crypto_pwhash_scryptsalsa208sha256(@Out byte[] buffer,
                                                      @u_int64_t long outlen,
                                                      @In byte[] passwd,
                                                      @u_int64_t long passwdlen,
                                                      @In byte[] salt,
                                                      @u_int64_t long opslimit,
                                                      @u_int64_t long memlimit);

        public int crypto_pwhash_scryptsalsa208sha256_str(@Out byte[] buffer,
                                                          @In byte[] passwd,
                                                          @u_int64_t long passwdlen,
                                                          @u_int64_t long opslimit,
                                                          @u_int64_t long memlimit);

        public int crypto_pwhash_scryptsalsa208sha256_str_verify(@In byte[] buffer,
                                                                 @In byte[] passwd,
                                                                 @u_int64_t long passwdlen);

        // ---------------------------------------------------------------------
        // Advanced: AES256-GCM

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: SHA-2

        public static final int SHA256BYTES = 32;

        public int crypto_hash_sha256(@Out byte[] buffer, @In byte[] message, @u_int64_t long sizeof);

        public static final int SHA512BYTES = 64;

        public int crypto_hash_sha512(@Out byte[] buffer, @In byte[] message, @u_int64_t long sizeof);

        // ---------------------------------------------------------------------
        // Advanced: HMAC-SHA-2

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: One-time authentication

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: Diffie-Hellman

        public static final int SCALAR_BYTES = 32;

        public int crypto_scalarmult_curve25519(@Out byte[] result, @In byte[] intValue, @In byte[] point);

        // ---------------------------------------------------------------------
        // Advanced: Stream ciphers: ChaCha20

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: Stream ciphers: Salsa20

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: Stream ciphers: XSalsa20

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: Ed25519 to Curve25519

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
