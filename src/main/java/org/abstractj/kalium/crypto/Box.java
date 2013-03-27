package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl.Sodium;
import org.abstractj.kalium.encoders.Hex;
import org.abstractj.kalium.keys.PrivateKey;
import org.abstractj.kalium.keys.PublicKey;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;

/**
 * Based on Curve25519XSalsa20Poly1305 and Box classes from rbnacl
 */
public class Box {

    private static final Sodium sodium = SODIUM_INSTANCE;

    private static final int NONCE_BYTES = 24;
    private static final int BEFORE_NMBYTES = 32;

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public Box(PrivateKey privateKey, PublicKey publicKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String encrypt(byte[] nonce, String message) {
        byte[] msg = new byte[32 + message.length()];
        byte[] ct = new byte[msg.length];
        sodium.crypto_box_curve25519xsalsa20poly1305_ref_afternm(ct, msg, msg.length, nonce, beforenm());
        return new String(Hex.encodeHex(ct));
    }

    private byte[] beforenm() {
        byte[] k = new byte[BEFORE_NMBYTES];
        sodium.crypto_box_curve25519xsalsa20poly1305_ref_beforenm(k, publicKey.getBytes(), privateKey.getBytes());
        return k;
    }
}
