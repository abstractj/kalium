package org.abstractj.kalium.keys;

import org.abstractj.kalium.crypto.Util;
import org.abstractj.kalium.encoders.Hex;

import static org.abstractj.kalium.NaCl.Sodium.PUBLICKEY_BYTES;

public class PublicKey {

    private final byte[] publicKey;

    public PublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
        Util.checkLength(publicKey, PUBLICKEY_BYTES);
    }

    public PublicKey(String publicKey) {
        this.publicKey = Hex.decodeHexString(publicKey);
    }

    public byte[] getBytes() {
        return publicKey;
    }
}
