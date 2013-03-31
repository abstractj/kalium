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

import static org.abstractj.kalium.NaCl.Sodium.BOXZERO_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.NONCE_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.XSALSA20_POLY1305_SECRETBOX_KEYBYTES;
import static org.abstractj.kalium.NaCl.Sodium.ZERO_BYTES;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;
import static org.abstractj.kalium.crypto.Util.isValid;

import org.abstractj.kalium.NaCl.Sodium;
import org.abstractj.kalium.encoders.Hex;

public class SecretBox {

    private static final Sodium sodium = SODIUM_INSTANCE;

    private final byte[] key;

    public SecretBox(byte[] key) {
        this.key = key;
        Util.checkLength(key, XSALSA20_POLY1305_SECRETBOX_KEYBYTES);
    }

    public SecretBox(String key){
        this.key = Hex.decodeHexString(key);
        Util.checkLength(this.key, XSALSA20_POLY1305_SECRETBOX_KEYBYTES);
    }
    public byte[] encrypt(byte[] nonce, byte[] message) {
        Util.checkLength(nonce, NONCE_BYTES);
        byte[] msg = Util.prependZeros(ZERO_BYTES, message);
        byte[] ct = Util.zeros(msg.length);
        isValid(sodium.crypto_secretbox_xsalsa20poly1305_ref(ct, msg, msg.length,
                nonce, key), "Encryption failed");
        return Util.removeZeros(BOXZERO_BYTES, ct);
    }

    public byte[] decrypt(byte[] nonce, byte[] ciphertext) {
        Util.checkLength(nonce, NONCE_BYTES);
        byte[] ct = Util.prependZeros(BOXZERO_BYTES, ciphertext);
        byte[] message = Util.zeros(ct.length);
        isValid(sodium.crypto_secretbox_xsalsa20poly1305_ref_open(message, ct,
                ct.length, nonce, key), "Decryption failed. Ciphertext failed verification");
        return Util.removeZeros(ZERO_BYTES, message);
    }
}
