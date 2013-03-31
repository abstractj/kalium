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
package org.abstractj.kalium.keys;

import org.abstractj.kalium.NaCl.Sodium;
import org.abstractj.kalium.crypto.Random;
import org.abstractj.kalium.crypto.Util;
import org.abstractj.kalium.encoders.Hex;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;
import static org.abstractj.kalium.NaCl.Sodium.PUBLICKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SECRETKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SIGNATURE_BYTES;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.crypto.Util.isValid;
import static org.abstractj.kalium.crypto.Util.slice;
import static org.abstractj.kalium.crypto.Util.zeros;

public class SigningKey {

    private static final Sodium sodium = SODIUM_INSTANCE;

    private final byte[] seed;
    private byte[] secretKey;
    private byte[] publicKey;

    public SigningKey() {
        this.seed = new Random().randomBytes(SECRETKEY_BYTES);
        checkLength(this.seed, SECRETKEY_BYTES);
    }

    public SigningKey(byte[] seed) {
        this.seed = seed;
        checkLength(this.seed, SECRETKEY_BYTES);
    }

    public SigningKey(String seed) {
        this.seed = Hex.decodeHexString(seed);
        checkLength(this.seed, SECRETKEY_BYTES);
    }

    public SigningKey generate() {
        publicKey = zeros(PUBLICKEY_BYTES);
        secretKey = zeros(SECRETKEY_BYTES * 2);
        isValid(sodium.crypto_sign_ed25519_ref_seed_keypair(publicKey, secretKey, seed),
                "Failed to generate a key pair");
        return this;
    }

    public byte[] sign(byte[] message) {
        byte[] signature = Util.prependZeros(SIGNATURE_BYTES, message);
        byte[] bufferLen = Util.zeros(Long.SIZE);
        sodium.crypto_sign_ed25519_ref(signature, bufferLen, message, message.length, secretKey);
        signature = slice(signature, 0, SIGNATURE_BYTES);
        return signature;
    }

    public byte[] getBytes() {
        return secretKey;
    }

    public String toHex() {
        return Hex.encodeHexString(secretKey);
    }
}
