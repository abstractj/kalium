package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl.Sodium;
import org.abstractj.kalium.encoders.Hex;
import org.abstractj.kalium.keys.PrivateKey;
import org.abstractj.kalium.keys.PublicKey;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;
import static org.abstractj.kalium.NaCl.Sodium.BOXZERO_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.CURVE25519_XSALSA20_POLY1305_BOX_BEFORE_NMBYTES;
import static org.abstractj.kalium.NaCl.Sodium.NONCE_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.PUBLICKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SECRETKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.ZERO_BYTES;

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
        Util.checkLength(publicKey.getBytes(), PUBLICKEY_BYTES);
        Util.checkLength(privateKey.getBytes(), SECRETKEY_BYTES);
    }

    public Box(String publicKey, String privateKey) {
        this.publicKey = Hex.decodeHexString(publicKey);
        this.privateKey = Hex.decodeHexString(privateKey);
        Util.checkLength(this.publicKey, PUBLICKEY_BYTES);
        Util.checkLength(this.privateKey, SECRETKEY_BYTES);
    }

    public byte[] encrypt(byte[] nonce, byte[] message) {
        Util.checkLength(nonce, NONCE_BYTES);
        byte[] msg = Util.prependZeros(ZERO_BYTES, message);
        byte[] ct = new byte[msg.length];
        sodium.crypto_box_curve25519xsalsa20poly1305_ref_afternm(ct, msg, msg.length, nonce, beforenm());
        return Util.removeZeros(BOXZERO_BYTES, ct);
    }

    public byte[] decrypt(byte[] nonce, byte[] ciphertext) {
        Util.checkLength(nonce, NONCE_BYTES);
        byte[] ct = Util.prependZeros(BOXZERO_BYTES, ciphertext);
        byte[] message = new byte[ct.length];
        int i = sodium.crypto_box_curve25519xsalsa20poly1305_ref_open_afternm(message, ct, ct.length, nonce, beforenm());
        return Util.removeZeros(ZERO_BYTES, message);
    }

    private byte[] beforenm() {
        byte[] k = new byte[CURVE25519_XSALSA20_POLY1305_BOX_BEFORE_NMBYTES];
        sodium.crypto_box_curve25519xsalsa20poly1305_ref_beforenm(k, publicKey, privateKey);
        return k;
    }
}
