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

package org.abstractj.kalium.crypto;

import org.abstractj.kalium.encoders.Encoder;

import static org.abstractj.kalium.NaCl.Sodium.*;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.crypto.Util.isValid;
import static org.abstractj.kalium.crypto.Util.zeros;

public class Hash {

    public interface MultiPartHash {
        MultiPartHash init();
        MultiPartHash update(byte[] in);
        byte[] done();
    }

    public MultiPartHash sha256() {
        return new MultiPartHash() {
            byte[] state = new byte[sodium().crypto_hash_sha256_statebytes()];

            @Override
            public MultiPartHash init() {
                sodium().crypto_hash_sha256_init(state);
                return this;
            }

            @Override
            public MultiPartHash update(byte[] in) {
                sodium().crypto_hash_sha256_update(state, in, in.length);
                return this;
            }

            @Override
            public byte[] done() {
                byte[] out = zeros(CRYPTO_HASH_SHA256_BYTES);
                sodium().crypto_hash_sha256_final(state, out);
                return out;
            }
        };
    }

    public byte[] sha256(byte[] message) {
        byte[] buffer = new byte[CRYPTO_HASH_SHA256_BYTES];
        sodium().crypto_hash_sha256(buffer, message, message.length);
        return buffer;
    }

    public MultiPartHash sha512() {
        return new MultiPartHash() {
            byte[] state = new byte[sodium().crypto_hash_sha512_statebytes()];

            @Override
            public MultiPartHash init() {
                sodium().crypto_hash_sha512_init(state);
                return this;
            }

            @Override
            public MultiPartHash update(byte[] in) {
                sodium().crypto_hash_sha512_update(state, in, in.length);
                return this;
            }

            @Override
            public byte[] done() {
                byte[] out = zeros(CRYPTO_HASH_SHA512_BYTES);
                sodium().crypto_hash_sha512_final(state, out);
                return out;
            }
        };
    }

    public byte[] sha512(byte[] message) {
        byte[] buffer = new byte[CRYPTO_HASH_SHA512_BYTES];
        sodium().crypto_hash_sha512(buffer, message, message.length);
        return buffer;
    }

    public String sha256(String message, Encoder encoder) {
        byte[] hash = sha256(message.getBytes());
        return encoder.encode(hash);
    }

    public String sha512(String message, Encoder encoder) {
        byte[] hash = sha512(message.getBytes());
        return encoder.encode(hash);
    }


    public byte[] blake2(byte[] message) throws UnsupportedOperationException {
        byte[] buffer = new byte[CRYPTO_GENERICHASH_BYTES_MAX];
        sodium().crypto_generichash(buffer, CRYPTO_GENERICHASH_BYTES_MAX, message, message.length, null, 0);
        return buffer;
    }

    public String blake2(String message, Encoder encoder) throws UnsupportedOperationException {
        byte[] hash = blake2(message.getBytes());
        return encoder.encode(hash);
    }

    public byte[] blake2(byte[] message, byte[] key, byte[] salt, byte[] personal) throws UnsupportedOperationException {
        byte[] buffer = new byte[CRYPTO_GENERICHASH_BYTES_MAX];
        sodium().crypto_generichash_blake2b_salt_personal(buffer, CRYPTO_GENERICHASH_BYTES_MAX,
                                                          message, message.length,
                                                          key, key.length,
                                                          salt, personal);
        return buffer;
    }

    public byte[] shortHash(byte[] message, byte[] key) {
        checkLength(key, CRYPTO_SHORTHASH_KEYBYTES);
        byte[] out = zeros(CRYPTO_SHORTHASH_BYTES);

        // Always returns 0 but check it for consistency
        isValid(sodium().crypto_shorthash(out, message, message.length, key),
                "Failed to generate hash.");
        return out;
    }
}
