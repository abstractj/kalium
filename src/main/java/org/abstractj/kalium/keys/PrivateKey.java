package org.abstractj.kalium.keys;

import org.abstractj.kalium.util.Hex;

import java.io.UnsupportedEncodingException;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;
import static org.abstractj.kalium.NaCl.Sodium;

public class PrivateKey {

    private static final Sodium sodium = SODIUM_INSTANCE;

    public static final int PUBLICKEY_BYTES = 32;
    public static final int SECRETKEY_BYTES = 32;

    private static byte[] publicKey;
    private static byte[] secretKey;

    private PrivateKey() {
    }

    public static PrivateKey generate() throws UnsupportedEncodingException {
        publicKey = new byte[PUBLICKEY_BYTES];
        secretKey = new byte[SECRETKEY_BYTES];
        sodium.crypto_box_curve25519xsalsa20poly1305_ref_keypair(publicKey, secretKey);
        return new PrivateKey();
    }

    public String toHex(){
        return Hex.encodeHexString(secretKey);
    }

    public PublicKey getPublicKey() {
         return new PublicKey(publicKey);
    }
}
