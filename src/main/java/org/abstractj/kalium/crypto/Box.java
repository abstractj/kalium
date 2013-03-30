package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl.Sodium;
import org.abstractj.kalium.encoders.Hex;
import org.abstractj.kalium.keys.PrivateKey;
import org.abstractj.kalium.keys.PublicKey;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;
import static org.abstractj.kalium.NaCl.Sodium.BOXZERO_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.NONCE_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.PUBLICKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SECRETKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.ZERO_BYTES;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.crypto.Util.isValid;
import static org.abstractj.kalium.crypto.Util.prependZeros;
import static org.abstractj.kalium.crypto.Util.removeZeros;

/**
 * Based on Curve25519XSalsa20Poly1305 and Box classes from rbnacl
 */
public class Box {

    private static final Sodium sodium = SODIUM_INSTANCE;

    private final byte[] privateKey;
    private final byte[] publicKey;


    public Box(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey.getBytes();
        this.privateKey = privateKey.getBytes();
        checkLength(publicKey.getBytes(), PUBLICKEY_BYTES);
        checkLength(privateKey.getBytes(), SECRETKEY_BYTES);
    }

    public Box(String publicKey, String privateKey) {
        this.publicKey = Hex.decodeHexString(publicKey);
        this.privateKey = Hex.decodeHexString(privateKey);
        checkLength(this.publicKey, PUBLICKEY_BYTES);
        checkLength(this.privateKey, SECRETKEY_BYTES);
    }

    public byte[] encrypt(byte[] nonce, byte[] message) {
        checkLength(nonce, NONCE_BYTES);
        byte[] msg = prependZeros(ZERO_BYTES, message);
        byte[] ct = new byte[msg.length];
        isValid(sodium.crypto_box_curve25519xsalsa20poly1305_ref(ct, msg,
                msg.length, nonce, publicKey, privateKey), "Encryption failed");
        return removeZeros(BOXZERO_BYTES, ct);
    }

    public byte[] decrypt(byte[] nonce, byte[] ciphertext) {
        checkLength(nonce, NONCE_BYTES);
        byte[] ct = prependZeros(BOXZERO_BYTES, ciphertext);
        byte[] message = new byte[ct.length];
        isValid(sodium.crypto_box_curve25519xsalsa20poly1305_ref_open(message, ct,
                message.length, nonce, publicKey, privateKey), "Decryption failed. Ciphertext failed verification.");
        return removeZeros(ZERO_BYTES, message);
    }
}
