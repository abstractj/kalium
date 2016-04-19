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

package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.encoders.Encoder;
import org.abstractj.kalium.keys.PrivateKey;
import org.abstractj.kalium.keys.PublicKey;

import static org.abstractj.kalium.NaCl.Sodium.*;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.*;

/**
 * Based on Curve25519XSalsa20Poly1305 and Box classes from rbnacl
 */
public class Box {

    private final byte[] sharedKey;

    public Box(byte[] publicKey, byte[] privateKey) {
        checkLength(publicKey, CRYPTO_BOX_PUBLICKEYBYTES);
        checkLength(privateKey, CRYPTO_BOX_SECRETKEYBYTES);

        sharedKey = zeros(NaCl.Sodium.CRYPTO_BOX_BEFORENMBYTES);
        isValid(sodium().crypto_box_beforenm(
                sharedKey, publicKey, privateKey), "Key agreement failed");
    }

    public Box(PublicKey publicKey, PrivateKey privateKey) {
        this(publicKey.toBytes(), privateKey.toBytes());
    }

    public Box(String publicKey, String privateKey, Encoder encoder) {
        this(encoder.decode(publicKey), encoder.decode(privateKey));
    }

    public byte[] encrypt(byte[] nonce, byte[] message) {
        checkLength(nonce, CRYPTO_BOX_NONCEBYTES);
        byte[] ct = zeros(message.length + CRYPTO_BOX_MACBYTES);
        isValid(sodium().crypto_box_easy_afternm(ct, message,
                message.length, nonce, sharedKey), "Encryption failed");
        return ct;
    }

    public byte[] encrypt(String nonce, String message, Encoder encoder) {
        return encrypt(encoder.decode(nonce), encoder.decode(message));
    }

    public byte[][] encryptDetached(byte[] nonce, byte[] message) {
        checkLength(nonce, CRYPTO_BOX_NONCEBYTES);
        byte[] ct = zeros(message.length);
        byte[] mac = zeros(CRYPTO_BOX_MACBYTES);
        isValid(sodium().crypto_box_detached_afternm(ct, mac, message,
                message.length, nonce, sharedKey), "Encryption failed");
        return new byte[][]{ct, mac};
    }

    public byte[] decrypt(byte[] nonce, byte[] ciphertext) {
        checkLength(nonce, CRYPTO_BOX_NONCEBYTES);
        byte[] message = zeros(ciphertext.length - CRYPTO_BOX_MACBYTES);
        isValid(sodium().crypto_box_open_easy_afternm(
                        message, ciphertext, ciphertext.length, nonce, sharedKey),
                "Decryption failed. Ciphertext failed verification.");
        return message;
    }

    public byte[] decryptDetached(byte[] nonce, byte[] ciphertext, byte[] mac) {
        checkLength(nonce, CRYPTO_BOX_NONCEBYTES);
        checkLength(mac, CRYPTO_BOX_MACBYTES);
        byte[] message = zeros(ciphertext.length);
        isValid(sodium().crypto_box_open_detached_afternm(
                        message, ciphertext, mac, message.length, nonce,
                        sharedKey),
                "Decryption failed. Ciphertext failed verification.");
        return message;
    }

    public byte[] decrypt(String nonce, String ciphertext, Encoder encoder) {
        return decrypt(encoder.decode(nonce), encoder.decode(ciphertext));
    }
}
