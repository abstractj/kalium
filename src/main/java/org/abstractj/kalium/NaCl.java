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
import jnr.ffi.types.size_t;

public class NaCl {

    public static Sodium sodium() {
        Sodium sodium = SingletonHolder.SODIUM_INSTANCE;

        if (!(sodium.sodium_version_string().compareTo("1.0.4") >= 0)) {
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

        int CRYPTO_AUTH_BYTES = 32;

        int CRYPTO_AUTH_KEYBYTES = 32;

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

        /**
         * @deprecated use CRYPTO_BOX_PUBLICKEYBYTES
         */
        @Deprecated
        int PUBLICKEY_BYTES = 32;

        /**
         * @deprecated use CRYPTO_BOX_SECRETKEYBYTES
         */
        @Deprecated
        int SECRETKEY_BYTES = 32;

        /**
         * @deprecated use CRYPTO_BOX_NONCEBYTES
         */
        @Deprecated
        int NONCE_BYTES = 24;

        /**
         * @deprecated use CRYPTO_BOX_ZEROBYTES
         */
        @Deprecated
        int ZERO_BYTES = 32;

        /**
         * @deprecated use CRYPTO_BOX_BOXZEROBYTES
         */
        @Deprecated
        int BOXZERO_BYTES = 16;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES = 32;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES = 32;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES = 32;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES = 16;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES =
                CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES -
                        CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES = 24;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES = 32;

        int CRYPTO_BOX_PUBLICKEYBYTES =
                CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES;

        int CRYPTO_BOX_SECRETKEYBYTES =
                CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES;

        int CRYPTO_BOX_ZEROBYTES =
                CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES;

        int CRYPTO_BOX_BOXZEROBYTES =
                CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES;

        int CRYPTO_BOX_MACBYTES =
                CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES;

        int CRYPTO_BOX_NONCEBYTES =
                CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES;

        int CRYPTO_BOX_BEFORENMBYTES =
                CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES;

        /**
         * @deprecated use the documented crypto_box_keypair
         */
        @Deprecated
        int crypto_box_curve25519xsalsa20poly1305_keypair(
                @Out byte[] publicKey, @Out byte[] secretKey);

        int crypto_box_keypair(
                @Out byte[] publicKey, @Out byte[] secretKey);

        int crypto_box_seed_keypair(
                @Out byte[] publicKey, @Out byte[] secretKey, @In byte[] seed);

        int crypto_box_beforenm(
                @Out byte[] sharedkey, @In byte[] publicKey,
                @In byte[] privateKey);

        /**
         * @deprecated This is the original NaCl interface and not recommended
         *             use crypto_box_easy
         */
        @Deprecated
        int crypto_box_curve25519xsalsa20poly1305(
                @Out byte[] ct, @In byte[] msg, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] publicKey, @In byte[] privateKey);

        int crypto_box_easy(
                @Out byte[] ct, @In byte[] msg, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] publicKey, @In byte[] privateKey);

        int crypto_box_detached(
                @Out byte[] ct, @Out byte[] mac, @In byte[] message,
                @In @u_int64_t int length, @In byte[] nonce,
                @In byte[] publicKey, @In byte[] privateKey);

        int crypto_box_easy_afternm(
                @Out byte[] ct, @In byte[] msg, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] shared);

        int crypto_box_detached_afternm(
                @Out byte[] ct, @Out byte[] mac, @In byte[] message,
                @In @u_int64_t int length, @In byte[] nonce, @In byte[] key);

        /**
         * @deprecated This is the original NaCl interface and not recommended
         *             use crypto_box_easy_open
         */
        @Deprecated
        int crypto_box_curve25519xsalsa20poly1305_open(
                @Out byte[] message, @In byte[] ct, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] publicKey, @In byte[] privateKey);

        int crypto_box_open_easy(
                @Out byte[] message, @In byte[] ct, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] publicKey, @In byte[] privateKey);

        int crypto_box_open_detached(
                @Out byte[] message, @In byte[] ct, @In byte[] mac,
                @In @u_int64_t int length, @In byte[] nonce,
                @In byte[] publicKey, @In byte[] privateKey);

        int crypto_box_open_easy_afternm(
                @Out byte[] message, @In byte[] ct, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] shared);

        int crypto_box_open_detached_afternm(
                @Out byte[] message, @In byte[] ct, @In byte[] mac,
                @In @u_int64_t int length, @In byte[] nonce, @In byte[] key);

        // ---------------------------------------------------------------------
        // Public-key cryptography: Public-key signatures

        /**
         * @deprecated use the documented CRYPTO_SIGN_BYTES
         */
        @Deprecated
        int SIGNATURE_BYTES = 64;

        int CRYPTO_SIGN_ED25519_PUBLICKEYBYTES = 32;

        int CRYPTO_SIGN_ED25519_SECRETKEYBYTES = 64;

        int CRYPTO_SIGN_ED25519_BYTES = 64;

        int CRYPTO_SIGN_ED25519_SEEDBYTES = 32;

        int CRYPTO_SIGN_PUBLICKEYBYTES = CRYPTO_SIGN_ED25519_PUBLICKEYBYTES;

        int CRYPTO_SIGN_SECRETKEYBYTES = CRYPTO_SIGN_ED25519_SECRETKEYBYTES;

        int CRYPTO_SIGN_BYTES = CRYPTO_SIGN_ED25519_BYTES;

        int CRYPTO_SIGN_SEEDBYTES = CRYPTO_SIGN_ED25519_SEEDBYTES;

        int crypto_sign_keypair(
                @Out byte[] publicKey, @Out byte[] secretKey);

        /**
         * @deprecated use the documented crypto_sign_seed_keypair
         */
        @Deprecated
        int crypto_sign_ed25519_seed_keypair(
                @Out byte[] publicKey, @Out byte[] secretKey, @In byte[] seed);

        int crypto_sign_seed_keypair(
                @Out byte[] publicKey, @Out byte[] secretKey, @In byte[] seed);

        /**
         * @deprecated use the documented crypto_sign
         */
        @Deprecated
        int crypto_sign_ed25519(
                @Out byte[] buffer, @Out LongLongByReference bufferLen,
                @In byte[] message, @In @u_int64_t int length,
                @In byte[] secretKey);

        int crypto_sign(
                @Out byte[] buffer, @Out LongLongByReference bufferLen,
                @In byte[] message, @In @u_int64_t int length,
                @In byte[] secretKey);

        int crypto_sign_detached(
                @Out byte[] sig, @Out LongLongByReference sigLen,
                @In byte[] message, @In @u_int64_t int messageLen,
                @In byte[] secretKey);

        /**
         * @deprecated use the documented crypto_sign_open
         */
        @Deprecated
        int crypto_sign_ed25519_open(
                @Out byte[] buffer, @Out LongLongByReference bufferLen,
                @In byte[] sigAndMsg, @In @u_int64_t int length,
                @In byte[] key);

        int crypto_sign_open(
                @Out byte[] buffer, @Out LongLongByReference bufferLen,
                @In byte[] sigAndMsg, @In @u_int64_t int length,
                @In byte[] key);

        int crypto_sign_verify_detached(
                @In byte[] sig, @In byte[] message,
                @In @u_int64_t int messageLen, @In byte[] publicKey);

        int crypto_sign_ed25519_sk_to_seed(
                @Out byte[] seed, @In byte[] secretKey);

        int crypto_sign_ed25519_sk_to_pk(
                @Out byte[] publicKey, @In byte[] secretKey);

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

        /**
         * @deprecated use CRYPTO_GENERICHASH_BYTES_MAX
         */
        @Deprecated
        int BLAKE2B_OUTBYTES = 64;

        int CRYPTO_GENERICHASH_BLAKE2B_BYTES = 32;

        int CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN = 16;

        int CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX = 64;

        int CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES = 32;

        int CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN = 16;

        int CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX = 64;

        int CRYPTO_GENERICHASH_BYTES =
                CRYPTO_GENERICHASH_BLAKE2B_BYTES;

        int CRYPTO_GENERICHASH_BYTES_MIN =
                CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN;

        int CRYPTO_GENERICHASH_BYTES_MAX =
                CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX;

        int CRYPTO_GENERICHASH_KEYBYTES =
                CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES;

        int CRYPTO_GENERICHASH_KEYBYTES_MIN =
                CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN;

        int CRYPTO_GENERICHASH_KEYBYTES_MAX =
                CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX;

        /**
         * @deprecated use the documented crypto_generichash
         */
        @Deprecated
        int crypto_generichash_blake2b(
                @Out byte[] buffer, @In @u_int64_t int outLen,
                @In byte[] message, @u_int64_t int messageLen, @In byte[] key,
                @In @u_int64_t int keyLen);

        int crypto_generichash(
                @Out byte[] buffer, @In @u_int64_t int outLen,
                @In byte[] message, @u_int64_t int messageLen, @In byte[] key,
                @In @u_int64_t int keyLen);

        int crypto_generichash_blake2b_salt_personal(
                @Out byte[] buffer, @In @u_int64_t int outLen,
                @In byte[] message, @u_int64_t int messageLen, @In byte[] key,
                @In @u_int64_t int keyLen, @In byte[] salt,
                @In byte[] personal);

        int crypto_generichash_statebytes();

        int crypto_generichash_init(
                @In @Out byte[] state, @In byte[] key, @In @size_t int keyLen,
                @In @size_t int outLen);

        int crypto_generichash_update(
                @In @Out byte[] state, @In byte[] in, @In @u_int64_t int inLen);

        int crypto_generichash_final(
                @In @Out byte[] state, @Out byte[] out, @In @size_t int outLen);

        // ---------------------------------------------------------------------
        // Hashing: Short-input hashing

        int CRYPTO_SHORTHASH_BYTES = 8;

        int CRYPTO_SHORTHASH_KEYBYTES = 16;

        int crypto_shorthash(
                @Out byte[] out, @In byte[] in, @In @u_int64_t int inLen,
                @In byte[] key);

        // ---------------------------------------------------------------------
        // Password hashing

        /**
         * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES
         */
        @Deprecated
        int PWHASH_SCRYPTSALSA208SHA256_STRBYTES = 102;

        /**
         * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OUTBYTES
         */
        @Deprecated
        int PWHASH_SCRYPTSALSA208SHA256_OUTBYTES = 64;

        /**
         * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE
         */
        @Deprecated
        int PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE = 524288;

        /**
         * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
         */
        @Deprecated
        int PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE = 16777216;

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

        int CRYPTO_AEAD_AES256GCM_KEYBYTES = 32;

        int CRYPTO_AEAD_AES256GCM_NPUBBYTES = 12;

        int CRYPTO_AEAD_AES256GCM_ABYTES = 16;

        /**
         * @return 1 if the current CPU supports the AES256-GCM implementation,
         *         and 0 if it doesn't.
         */
        int crypto_aead_aes256gcm_is_available();

        int crypto_aead_aes256gcm_encrypt(
                @Out byte[] ct, @Out LongLongByReference ctLen, @In byte[] msg,
                @In @u_int64_t int msgLen, @In byte[] ad,
                @In @u_int64_t int adLen, @In byte[] nsec, @In byte[] npub,
                @In byte[] key);

        int crypto_aead_aes256gcm_decrypt(
                @Out byte[] msg, @Out LongLongByReference msgLen, @In byte[] nsec,
                @In byte[] ct, @In @u_int64_t int ctLen, @In byte[] ad,
                @In @u_int64_t int adLen, @In byte[] npub, @In byte[] key);

        int crypto_aead_aes256gcm_statebytes();

        int crypto_aead_aes256gcm_beforenm(
                @Out byte[] state, @In byte[] key);

        int crypto_aead_aes256gcm_encrypt_afternm(
                @Out byte[] ct, @Out LongLongByReference ctLen, @In byte[] msg,
                @In @u_int64_t int msgLen, @In byte[] ad,
                @In @u_int64_t int adLen, @In byte[] nsec, @In byte[] npub,
                @In @Out byte[] state);

        int crypto_aead_aes256gcm_decrypt_afternm(
                @Out byte[] ct, @Out LongLongByReference ctLen, @In byte[] msg,
                @In @u_int64_t int msgLen, @In byte[] ad,
                @In @u_int64_t int adLen, @In byte[] nsec, @In byte[] npub,
                @In @Out byte[] state);

        // ---------------------------------------------------------------------
        // Advanced: SHA-2

        /**
         * @deprecated use CRYPTO_HASH_SHA256_BYTES
         */
        int SHA256BYTES = 32;

        /**
         * @deprecated use CRYPTO_HASH_SHA512_BYTES
         */
        int SHA512BYTES = 64;

        int CRYPTO_HASH_SHA256_BYTES = 32;

        int CRYPTO_HASH_SHA512_BYTES = 64;

        int crypto_hash_sha256(
                @Out byte[] buffer, @In byte[] message,
                @In @u_int64_t int sizeof);

        int crypto_hash_sha256_statebytes();

        int crypto_hash_sha256_init(@Out byte[] state);

        int crypto_hash_sha256_update(
                @In @Out byte[] state, @In byte[] in, @In @u_int64_t int inLen);

        int crypto_hash_sha256_final(
                @In byte[] state, @Out byte[] out);

        int crypto_hash_sha512(
                @Out byte[] buffer, @In byte[] message,
                @In @u_int64_t int sizeof);

        int crypto_hash_sha512_statebytes();

        int crypto_hash_sha512_init(@Out byte[] state);

        int crypto_hash_sha512_update(
                @In @Out byte[] state, @In byte[] in, @In @u_int64_t int inLen);

        int crypto_hash_sha512_final(
                @In byte[] state, @Out byte[] out);

        // ---------------------------------------------------------------------
        // Advanced: HMAC-SHA-2

        int CRYPTO_AUTH_HMACSHA256_BYTES = 32;

        int CRYPTO_AUTH_HMACSHA256_KEYBYTES = 32;

        int CRYPTO_AUTH_HMACSHA512_BYTES = 64;

        int CRYPTO_AUTH_HMACSHA512_KEYBYTES = 32;

        int CRYPTO_AUTH_HMACSHA512256_BYTES = 32;

        int CRYPTO_AUTH_HMACSHA512256_KEYBYTES = 32;

        int crypto_auth_hmacsha256(
                @Out byte[] mac, @In byte[] in, @In @u_int64_t int inLen,
                @In byte[] key);

        int crypto_auth_hmacsha256_verify(
                @In byte[] mac, @In byte[] in, @In @u_int64_t int inLen,
                @In byte[] key);

        int crypto_hash_hmacsha256_statebytes();

        int crypto_auth_hmacsha256_init(
                @Out byte[] state, @In byte[] key, @In @size_t int keyLen);

        int crypto_auth_hmacsha256_update(
                @In @Out byte[] state, @In byte[] msg,
                @In @u_int64_t int msgLen);

        int crypto_auth_hmacsha256_final(
                @In byte[] state, @Out byte[] hmac);

        int crypto_auth_hmacsha512(
                @Out byte[] mac, @In byte[] in, @In @u_int64_t int inLen,
                @In byte[] key);

        int crypto_auth_hmacsha512_verify(
                @In byte[] mac, @In byte[] in, @In @u_int64_t int inLen,
                @In byte[] key);

        int crypto_hash_hmacsha512_statebytes();

        int crypto_auth_hmacsha512_init(
                @Out byte[] state, @In byte[] key, @In @size_t int keyLen);

        int crypto_auth_hmacsha512_update(
                @In @Out byte[] state, @In byte[] msg,
                @In @u_int64_t int msgLen);

        int crypto_auth_hmacsha512_final(
                @In byte[] state, @Out byte[] hmac);

        /**
         * @deprecated you should probably use the documented crypto_auth
         */
        int crypto_auth_hmacsha512256(
                @Out byte[] mac, @In byte[] message, @In @u_int64_t int sizeof,
                @In byte[] key);

        /**
         * @deprecated you should probably use the documented crypto_auth_verify
         */
        int crypto_auth_hmacsha512256_verify(
                @In byte[] mac, @In byte[] message, @In @u_int64_t int sizeof,
                @In byte[] key);

        int crypto_hash_hmacsha512256_statebytes();

        int crypto_auth_hmacsha512256_init(
                @Out byte[] state, @In byte[] key, @In @size_t int keyLen);

        int crypto_auth_hmacsha512256_update(
                @In @Out byte[] state, @In byte[] msg,
                @In @u_int64_t int msgLen);

        int crypto_auth_hmacsha512256_final(
                @In byte[] state, @Out byte[] hmac);

        // ---------------------------------------------------------------------
        // Advanced: One-time authentication

        int CRYPTO_ONETIMEAUTH_BYTES = 16;

        int CRYPTO_ONETIMEAUTH_KEYBYTES = 32;

        int crypto_onetimeauth(
                @Out byte[] tag, @In byte in, @In @u_int64_t int inLen,
                @In byte[] key);

        int crypto_onetimeauth_verify(
                @In byte[] tag, @In byte[] in, @In @u_int64_t int inLen,
                @In byte[] key);

        int crypto_onetimeauth_statebytes();

        int crypto_onetimeauth_init(
                @Out byte[] state, @In byte[] key);

        int crypto_onetimeauth_update(
                @In @Out byte[] state, @In byte[] in, @In @u_int64_t int inLen);

        int crypto_onetimeauth_final(
                @In byte[] state, @Out byte[] tag);

        // ---------------------------------------------------------------------
        // Advanced: Diffie-Hellman

        /**
         * @deprecated use CRYPTO_SCALARMULT_BYTES
         */
        @Deprecated
        int CRYPTO_SCALARMULT_CURVE25519_BYTES = 32;

        /**
         * @deprecated use CRYPTO_SCALARMULT_SCALARBYTES
         */
        @Deprecated
        int CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES = 32;

        int CRYPTO_SCALARMULT_BYTES = 32;

        int CRYPTO_SCALARMULT_SCALARBYTES = 32;

        /**
         * @deprecated use crypto_scalarmult
         */
        @Deprecated
        int crypto_scalarmult_curve25519(
                @Out byte[] result, @In byte[] intValue, @In byte[] point);

        int crypto_scalarmult(
                @Out byte[] q, @In byte[] n, @In byte[] p);

        int crypto_scalarmult_base(
                @Out byte[] q, @In byte[] n);

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
