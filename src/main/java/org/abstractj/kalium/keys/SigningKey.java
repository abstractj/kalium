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

package org.abstractj.kalium.keys;

import jnr.ffi.byref.LongLongByReference;
import org.abstractj.kalium.crypto.Util;
import org.abstractj.kalium.encoders.Encoder;

import static org.abstractj.kalium.NaCl.Sodium.SIGNATURE_SECRETKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SIGNATURE_SEED_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SIGNATURE_BYTES;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.crypto.Util.slice;
import static org.abstractj.kalium.encoders.Encoder.HEX;

public class SigningKey {
    private final byte[] secretKey;

    public SigningKey(byte[] secretKey) {
        checkLength(secretKey, SIGNATURE_SECRETKEY_BYTES);
        this.secretKey = secretKey;
    }

    public SigningKey(String secretKey, Encoder encoder) {
        this(encoder.decode(secretKey));
    }

    public byte[] sign(byte[] message) {
        byte[] signature = Util.prependZeros(SIGNATURE_BYTES, message);
        LongLongByReference bufferLen = new LongLongByReference(0);
        sodium().crypto_sign_ed25519_ref(signature, bufferLen, message, message.length, secretKey);
        signature = slice(signature, 0, SIGNATURE_BYTES);
        return signature;
    }

    public String sign(String message, Encoder encoder) {
        byte[] signature = sign(encoder.decode(message));
        return encoder.encode(signature);
    }

    public byte[] toSeed() {
        /* We happen to know that in the Ed25519 scheme that the keypair-generating seed
        is the first SIGNATURE_SEED_BYTES of the secretKey. */
        return Util.slice(secretKey, 0, SIGNATURE_SEED_BYTES);
    }

    public byte[] toBytes() {
        return secretKey;
    }

    @Override
    public String toString() {
        return HEX.encode(toSeed());
    }
}
