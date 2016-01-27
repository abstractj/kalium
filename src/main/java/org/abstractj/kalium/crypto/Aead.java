package org.abstractj.kalium.crypto;

import org.abstractj.kalium.encoders.Encoder;

import static org.abstractj.kalium.NaCl.Sodium.*;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.*;

public class Aead {

    private byte[] key;

    public Aead(byte[] key) {
        this.key = key;
        checkLength(key, CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES);
    }

    public Aead(String key, Encoder encoder) {
        this(encoder.decode(key));
    }

    public byte[] encrypt(byte[] publicNonce, byte[] message, byte[] additionalData) {
        checkLength(publicNonce, CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
        byte[] ct = zeros(message.length + CRYPTO_AEAD_CHACHA20POLY1305_ABYTES);
        isValid(sodium().crypto_aead_chacha20poly1305_encrypt(ct, null,
                        message, message.length, additionalData,
                        additionalData.length, null, publicNonce, key),
                "Encryption failed");

        return ct;
    }

    public byte[] decrypt(byte[] publicNonce, byte[] ciphertext, byte[] additionalData) {
        checkLength(publicNonce, CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
        byte[] msg = zeros(ciphertext.length - CRYPTO_AEAD_CHACHA20POLY1305_ABYTES);
        isValid(sodium().crypto_aead_chacha20poly1305_decrypt(msg, null,
                        null, ciphertext, ciphertext.length, additionalData,
                        additionalData.length, publicNonce, key),
                "Decryption failed. Ciphertext failed verification");

        return msg;
    }
}
