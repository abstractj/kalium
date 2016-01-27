/**
 * Copyright 2013 Bruno Oliveira, and individual contributors
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
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

        if (!(sodium.sodium_version_string().compareTo("1.0.3") >= 0)) {
            String message = String.format(
                    "Unsupported libsodium version: %s. Please update",
                    sodium.sodium_version_string());
            throw new UnsupportedOperationException(message);
        }
        return sodium;
    }

    private static final String LIBRARY_NAME = "sodium";

    private static final class SingletonHolder {
        public static final Sodium SODIUM_INSTANCE =
                LibraryLoader.create(Sodium.class)
                        .search("/usr/local/lib")
                        .search("/opt/local/lib")
                        .search("lib")
                        .load(LIBRARY_NAME);

    }

    private NaCl() {
    }

    public interface Sodium {

        /**
         * This function isn't thread safe. Be sure to call it once, and before
         * performing other operations.
         *
         * Check libsodium's documentation for more info.
         */
        int sodium_init();

        String sodium_version_string();

        // ---------------------------------------------------------------------
        // Generating Random Data

        void randombytes(@Out byte[] buffer, @In @u_int64_t int size);

        // ---------------------------------------------------------------------
        // Secret-key cryptography: Authenticated encryption

        /**
         * @deprecated use CRYPTO_SECRETBOX_KEYBYTES
         */
        @Deprecated
        int XSALSA20_POLY1305_SECRETBOX_KEYBYTES = 32;

        /**
         * @deprecated use CRYPTO_SECRETBOX_NONCEBYTES
         */
        @Deprecated
        int XSALSA20_POLY1305_SECRETBOX_NONCEBYTES = 24;

        int CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES = 32;

        int CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES = 24;

        int CRYPTO_SECRETBOX_XSALSA20POLY1305_ZEROBYTES = 32;

        int CRYPTO_SECRETBOX_XSALSA20POLY1305_BOXZEROBYTES = 16;

        int CRYPTO_SECRETBOX_XSALSA20POLY1305_MACBYTES =
                CRYPTO_SECRETBOX_XSALSA20POLY1305_ZEROBYTES -
                        CRYPTO_SECRETBOX_XSALSA20POLY1305_BOXZEROBYTES;

        int CRYPTO_SECRETBOX_KEYBYTES =
                CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES;

        int CRYPTO_SECRETBOX_NONCEBYTES =
                CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES;

        int CRYPTO_SECRETBOX_ZEROBYTES =
                CRYPTO_SECRETBOX_XSALSA20POLY1305_ZEROBYTES;

        int CRYPTO_SECRETBOX_BOXZEROBYTES =
                CRYPTO_SECRETBOX_XSALSA20POLY1305_BOXZEROBYTES;

        int CRYPTO_SECRETBOX_MACBYTES =
                CRYPTO_SECRETBOX_XSALSA20POLY1305_MACBYTES;

        /**
         * @deprecated This is the original NaCl interface and not recommended
         */
        @Deprecated
        int crypto_secretbox_xsalsa20poly1305( // crypto_secretbox
                @Out byte[] ct, @In byte[] msg, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] key);

        /**
         * @deprecated This is the original NaCl interface and not recommended
         */
        @Deprecated
        int crypto_secretbox_xsalsa20poly1305_open( // crypto_secretbox_open
                @Out byte[] message, @In byte[] ct, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] key);

        int crypto_secretbox_easy(
                @Out byte[] ct, @In byte[] msg, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] key);

        int crypto_secretbox_open_easy(
                @Out byte[] message, @In byte[] ct, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] key);

        int crypto_secretbox_detached(
                @Out byte[] ct, @Out byte[] mac, @In byte[] msg,
                @In @u_int64_t int length, @In byte[] nonce, @In byte[] key);

        int crypto_secretbox_open_detached(
                @Out byte[] message, @In byte[] ct, @In byte[] mac,
                @In @u_int64_t int length, @In byte[] nonce, @In byte[] key);

        // ---------------------------------------------------------------------
        // Secret-key cryptography: Authentication

        /**
         * @deprecated use CRYPTO_AUTH_BYTES
         */
        @Deprecated
        int HMACSHA512256_BYTES = 32;

        /**
         * @deprecated use CRYPTO_AUTH_KEYBYTES
         */
        @Deprecated
        int HMACSHA512256_KEYBYTES = 32;

        int CRYPTO_AUTH_HMACSHA512256_BYTES = 32;

        int CRYPTO_AUTH_HMACSHA512256_KEYBYTES = 32;

        int CRYPTO_AUTH_BYTES = CRYPTO_AUTH_HMACSHA512256_BYTES;

        int CRYPTO_AUTH_KEYBYTES = CRYPTO_AUTH_HMACSHA512256_KEYBYTES;

        /**
         * @deprecated use the documented crypto_auth
         */
        @Deprecated
        int crypto_auth_hmacsha512256(
                @Out byte[] mac, @In byte[] message, @In @u_int64_t int sizeof,
                @In byte[] key);

        /**
         * @deprecated use the documented crypto_auth_verify
         */
        @Deprecated
        int crypto_auth_hmacsha512256_verify(
                @In byte[] mac, @In byte[] message, @In @u_int64_t int sizeof,
                @In byte[] key);

        int crypto_auth(
                @Out byte[] mac, @In byte[] message, @In @u_int64_t int sizeof,
                @In byte[] key);

        int crypto_auth_verify(
                @In byte[] mac, @In byte[] message, @In @u_int64_t int sizeof,
                @In byte[] key);

        // ---------------------------------------------------------------------
        // Secret-key cryptography: AEAD

        int CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES = 32;

        int CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES = 8;

        int CRYPTO_AEAD_CHACHA20POLY1305_ABYTES = 16;

        int crypto_aead_chacha20poly1305_encrypt(
                @Out byte[] ct, @Out LongLongByReference ctLength,
                @In byte[] message, @In @u_int64_t int messageLength,
                @In byte[] additionalData, @In @u_int64_t int adLength,
                @In byte[] nsec, @In byte[] npub, @In byte[] key);

        int crypto_aead_chacha20poly1305_decrypt(
                @Out byte[] message, @Out LongLongByReference messageLength,
                @In byte[] nsec, @In byte[] ct, @In @u_int64_t int ctLength,
                @In byte[] additionalData, @In @u_int64_t int adLength,
                @In byte[] npub, @In byte[] key);

        // ---------------------------------------------------------------------
        // Public-key cryptography: Authenticated encryption

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES = 32;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES = 32;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES = 32;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES = 16;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES =
                CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES -
                        CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES = 24;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES = 32;

        int crypto_box_curve25519xsalsa20poly1305_keypair(
                @Out byte[] publicKey, @Out byte[] secretKey);

        int crypto_box_curve25519xsalsa20poly1305_beforenm(
                @Out byte[] sharedkey, @In byte[] publicKey,
                @In byte[] privateKey);

        int crypto_box_curve25519xsalsa20poly1305(
                @Out byte[] ct, @In byte[] msg, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] publicKey, @In byte[] privateKey);

        int crypto_box_curve25519xsalsa20poly1305_afternm(
                @Out byte[] ct, @In byte[] msg, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] shared);

        int crypto_box_curve25519xsalsa20poly1305_open(
                @Out byte[] message, @In byte[] ct, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] publicKey, @In byte[] privateKey);

        int crypto_box_curve25519xsalsa20poly1305_open_afternm(
                @Out byte[] message, @In byte[] ct, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] shared);

        // ---------------------------------------------------------------------
        // Public-key cryptography: Public-key signatures

        int CRYPTO_SIGN_ED25519_PUBLICKEYBYTES = 32;

        int CRYPTO_SIGN_ED25519_SECRETKEYBYTES = 64;

        int CRYPTO_SIGN_ED25519_BYTES = 64;

        int crypto_sign_ed25519_seed_keypair(
                @Out byte[] publicKey, @Out byte[] secretKey, @In byte[] seed);

        int crypto_sign_ed25519(
                @Out byte[] buffer, @Out LongLongByReference bufferLen,
                @In byte[] message, @In @u_int64_t int length,
                @In byte[] secretKey);

        int crypto_sign_ed25519_open(
                @Out byte[] buffer, @Out LongLongByReference bufferLen,
                @In byte[] sigAndMsg, @In @u_int64_t int length,
                @In byte[] key);

        // ---------------------------------------------------------------------
        // Public-key cryptography: Sealed boxes

        int CRYPTO_BOX_SEALBYTES =
                CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES +
                        CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES;

        int crypto_box_seal(
                @Out byte[] ct, @In byte[] message, @In @u_int64_t int length,
                @In byte[] publicKey);

        int crypto_box_seal_open(
                @Out byte[] message, @In byte[] c, @In @u_int64_t int length,
                @In byte[] publicKey, @In byte[] privateKey);

        // ---------------------------------------------------------------------
        // Hashing: Generic hashing

//        int CRYPTO_GENERICHASH_BLAKE2B_BYTES = 32; libsodium defines it as 32
        int CRYPTO_GENERICHASH_BLAKE2B_BYTES = 64;

        int CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN = 16;

        int CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX = 64;

        int CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES = 32;

        int CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN = 16;

        int CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX = 64;

        int crypto_generichash_blake2b(
                @Out byte[] buffer, @In @u_int64_t int outLen,
                @In byte[] message, @u_int64_t int messageLen, @In byte[] key,
                @In @u_int64_t int keyLen);

        int crypto_generichash_blake2b_salt_personal(
                @Out byte[] buffer, @In @u_int64_t int outLen,
                @In byte[] message, @u_int64_t int messageLen, @In byte[] key,
                @In @u_int64_t int keyLen, @In byte[] salt,
                @In byte[] personal);

        // ---------------------------------------------------------------------
        // Hashing: Short-input hashing

        // TODO

        // ---------------------------------------------------------------------
        // Password hashing

        int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES = 102;

        int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OUTBYTES = 64;

        int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE = 524288;

        int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE = 16777216;

        int crypto_pwhash_scryptsalsa208sha256(
                @Out byte[] buffer, @In @u_int64_t int outlen,
                @In byte[] passwd,
                @In @u_int64_t int passwdlen, @In byte[] salt,
                @In @u_int64_t long opslimit, @In @u_int64_t long memlimit);

        int crypto_pwhash_scryptsalsa208sha256_str(
                @Out byte[] buffer, @In byte[] passwd,
                @In @u_int64_t int passwdlen, @In @u_int64_t long opslimit,
                @In @u_int64_t long memlimit);

        int crypto_pwhash_scryptsalsa208sha256_str_verify(
                @In byte[] buffer, @In byte[] passwd,
                @In @u_int64_t int passwdlen);

        // ---------------------------------------------------------------------
        // Advanced: AES256-GCM

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: SHA-2

        int CRYPTO_HASH_SHA256_BYTES = 32;

        int crypto_hash_sha256(
                @Out byte[] buffer, @In byte[] message,
                @In @u_int64_t int sizeof);

        int CRYPTO_HASH_SHA512_BYTES = 64;

        int crypto_hash_sha512(
                @Out byte[] buffer, @In byte[] message,
                @In @u_int64_t int sizeof);

        // ---------------------------------------------------------------------
        // Advanced: HMAC-SHA-2

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: One-time authentication

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: Diffie-Hellman

        int CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES = 32;

        int CRYPTO_SCALARMULT_CURVE25519_BYTES = 32;

        int crypto_scalarmult_curve25519(
                @Out byte[] result, @In byte[] intValue, @In byte[] point);

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
     * This is a Java synchronized wrapper around libsodium's init function.
     * LibSodium's init function is not thread-safe.
     *
     * Check libsodium's documentation for more info.
     */
    public static synchronized int init() {
        return sodium().sodium_init();
    }
}
