package org.abstractj.kalium.keys;

import org.abstractj.kalium.crypto.Point;
import org.abstractj.kalium.encoders.Hex;

import java.io.UnsupportedEncodingException;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;
import static org.abstractj.kalium.NaCl.Sodium;
import static org.abstractj.kalium.NaCl.Sodium.PUBLICKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SECRETKEY_BYTES;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.crypto.Util.zeros;

public class PrivateKey {

    private static final Sodium sodium = SODIUM_INSTANCE;

    private static byte[] publicKey;
    private static byte[] secretKey;

    private PrivateKey() {
    }

    public PrivateKey(byte[] secretKey) {
        this.secretKey = secretKey;
        checkLength(this.secretKey, SECRETKEY_BYTES);
    }

    public PrivateKey(String secretKey) {
        this.secretKey = Hex.decodeHexString(secretKey);
        checkLength(this.secretKey, SECRETKEY_BYTES);
    }

    public static PrivateKey generate() throws UnsupportedEncodingException {
        secretKey = zeros(SECRETKEY_BYTES);
        publicKey = zeros(PUBLICKEY_BYTES);
        sodium.crypto_box_curve25519xsalsa20poly1305_ref_keypair(publicKey, secretKey);
        return new PrivateKey(secretKey);
    }

    public byte[] getBytes() {
        return secretKey;
    }

    public String toHex() {
        return Hex.encodeHexString(secretKey);
    }

    public PublicKey getPublicKey() {
        Point point = new Point();
        byte[] key = publicKey != null ? publicKey : point.mult(Hex.encodeHexString(secretKey)).toBytes();
        return new PublicKey(key);
    }
}
