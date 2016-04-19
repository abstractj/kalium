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
import static org.abstractj.kalium.crypto.Util.*;

public class SecretBox {

    private byte[] key;

    public SecretBox(byte[] key) {
        this.key = key;
        checkLength(key, CRYPTO_SECRETBOX_KEYBYTES);
    }

    public SecretBox(String key, Encoder encoder) {
        this(encoder.decode(key));
    }

    public byte[] encrypt(byte[] nonce, byte[] message) {
        checkLength(nonce, CRYPTO_SECRETBOX_NONCEBYTES);
        byte[] ct = zeros(message.length + CRYPTO_SECRETBOX_MACBYTES);
        isValid(sodium().crypto_secretbox_easy(ct, message, message.length,
                nonce, key), "Encryption failed");
        return ct;
    }

    public byte[][] encryptDetached(byte[] nonce, byte[] message) {
        checkLength(nonce, CRYPTO_SECRETBOX_NONCEBYTES);
        byte[] ct = zeros(message.length) ;
        byte[] mac = zeros(CRYPTO_SECRETBOX_MACBYTES);
        isValid(sodium().crypto_secretbox_detached(ct, mac, message,
                        message.length, nonce, key),
                "Encryption failed");
        return new byte[][] { ct, mac };
    }

    public byte[] decrypt(byte[] nonce, byte[] ciphertext) {
        checkLength(nonce, CRYPTO_SECRETBOX_NONCEBYTES);
        byte[] message = zeros(ciphertext.length - CRYPTO_SECRETBOX_MACBYTES);
        isValid(sodium().crypto_secretbox_open_easy(message, ciphertext,
                        ciphertext.length, nonce, key),
                "Decryption failed. Ciphertext failed verification");
        return message;
    }

    public byte[] decryptDetached(byte[] nonce, byte[] ciphertext, byte[] mac) {
        checkLength(nonce, CRYPTO_SECRETBOX_NONCEBYTES);
        byte[] message = zeros(ciphertext.length);
        isValid(sodium().crypto_secretbox_open_detached(message, ciphertext,
                        mac, ciphertext.length, nonce, key),
                "Decryption failed. Ciphertext failed verification");
        return message;
    }
}
