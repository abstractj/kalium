package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl.Sodium;
import org.abstractj.kalium.keys.PrivateKey;
import org.abstractj.kalium.keys.PublicKey;

import java.io.UnsupportedEncodingException;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;
import static org.abstractj.kalium.NaCl.Sodium.NONCE_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.PUBLICKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SECRETKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.CURVE25519_XSALSA20_POLY1305_BOX_BEFORE_NMBYTES;
import static org.abstractj.kalium.NaCl.Sodium.BOXZERO_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.ZERO_BYTES;

/**
 * Based on Curve25519XSalsa20Poly1305 and Box classes from rbnacl
 */
public class Box {

    private static final Sodium sodium = SODIUM_INSTANCE;

    private final byte[] privateKey;
    private final byte[] publicKey;

    public Box(PrivateKey privateKey, PublicKey publicKey) {
        this.publicKey = publicKey.getBytes();
        this.privateKey = privateKey.getBytes();
        Util.checkLength(publicKey.getBytes(), PUBLICKEY_BYTES);
        Util.checkLength(privateKey.getBytes(), SECRETKEY_BYTES);
    }

    public Box(byte[] privateKey, byte[] publicKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        Util.checkLength(publicKey, PUBLICKEY_BYTES);
        Util.checkLength(privateKey, SECRETKEY_BYTES);
    }

    public byte[] encrypt(byte[] nonce, String message) {
        Util.checkLength(nonce, NONCE_BYTES);
        byte[] msg = Util.prependZeros(ZERO_BYTES, message);
        byte[] ct = new byte[msg.length];
        sodium.crypto_box_curve25519xsalsa20poly1305_ref_afternm(ct, msg, msg.length, nonce, beforenm());
        return Util.removeZeros(BOXZERO_BYTES, ct);
    }

    public byte[] decrypt(byte[] nonce, String ciphertext){
        Util.checkLength(nonce, NONCE_BYTES);
        return null;
    }

    private byte[] beforenm() {
        byte[] k = new byte[CURVE25519_XSALSA20_POLY1305_BOX_BEFORE_NMBYTES];
        sodium.crypto_box_curve25519xsalsa20poly1305_ref_beforenm(k, publicKey, privateKey);
        return k;
    }
}
