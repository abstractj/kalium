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

import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.encoders.Encoder;
import org.abstractj.kalium.keys.PrivateKey;
import org.abstractj.kalium.keys.PublicKey;

import static org.abstractj.kalium.NaCl.Sodium.BOXZERO_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.NONCE_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.PUBLICKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SECRETKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.ZERO_BYTES;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.crypto.Util.isValid;
import static org.abstractj.kalium.crypto.Util.prependZeros;
import static org.abstractj.kalium.crypto.Util.removeZeros;

/**
 * Based on Curve25519XSalsa20Poly1305 and Box classes from rbnacl
 */
public class Box {

    private final byte[] sharedKey;

    public Box(byte[] publicKey, byte[] privateKey) {
        checkLength(publicKey, PUBLICKEY_BYTES);
        checkLength(privateKey, SECRETKEY_BYTES);

        sharedKey = new byte[NaCl.Sodium.BEFORENMBYTES];
        isValid(sodium().crypto_box_curve25519xsalsa20poly1305_beforenm(
                sharedKey, publicKey, privateKey), "Key agreement failed");
    }

    public Box(PublicKey publicKey, PrivateKey privateKey) {
        this(publicKey.toBytes(), privateKey.toBytes());
    }

    public Box(String publicKey, String privateKey, Encoder encoder) {
        this(encoder.decode(publicKey), encoder.decode(privateKey));
    }

    public byte[] encrypt(byte[] nonce, byte[] message) {
        checkLength(nonce, NONCE_BYTES);
        byte[] msg = prependZeros(ZERO_BYTES, message);
        byte[] ct = new byte[msg.length];
        isValid(sodium().crypto_box_curve25519xsalsa20poly1305_afternm(ct, msg,
                msg.length, nonce, sharedKey), "Encryption failed");
        return removeZeros(BOXZERO_BYTES, ct);
    }

    public byte[] encrypt(String nonce, String message, Encoder encoder) {
        return encrypt(encoder.decode(nonce), encoder.decode(message));
    }

    public byte[] decrypt(byte[] nonce, byte[] ciphertext) {
        checkLength(nonce, NONCE_BYTES);
        byte[] ct = prependZeros(BOXZERO_BYTES, ciphertext);
        byte[] message = new byte[ct.length];
        isValid(sodium().crypto_box_curve25519xsalsa20poly1305_open_afternm(
                        message, ct, message.length, nonce, sharedKey),
                "Decryption failed. Ciphertext failed verification.");
        return removeZeros(ZERO_BYTES, message);
    }

    public byte[] decrypt(String nonce, String ciphertext, Encoder encoder) {
        return decrypt(encoder.decode(nonce), encoder.decode(ciphertext));
    }
}
