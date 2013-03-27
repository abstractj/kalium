package org.abstractj.kalium.keys;

import org.abstractj.kalium.encoders.Hex;

import java.io.UnsupportedEncodingException;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;
import static org.abstractj.kalium.NaCl.Sodium;
import static org.abstractj.kalium.NaCl.Sodium.PUBLICKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SECRETKEY_BYTES;

public class PrivateKey {

    private static final Sodium sodium = SODIUM_INSTANCE;

    private static byte[] publicKey;
    private static byte[] privateKey;

    private PrivateKey(){}

    public PrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }

    public PrivateKey(String privateKey) {
        this.privateKey = Hex.decodeHex(privateKey.toCharArray());
    }

    public static PrivateKey generate() throws UnsupportedEncodingException {
        publicKey = new byte[PUBLICKEY_BYTES];
        privateKey = new byte[SECRETKEY_BYTES];
        sodium.crypto_box_curve25519xsalsa20poly1305_ref_keypair(publicKey, privateKey);
        return new PrivateKey();
    }

    public byte[] getBytes() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return new PublicKey(publicKey);
    }
}
