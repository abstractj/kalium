package org.abstractj.kalium.keys;

import org.abstractj.kalium.encoders.Hex;

public class PublicKey {

    private final byte[] publicKey;

    public PublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public PublicKey(String publicKey) {
        this.publicKey = Hex.decodeHex(publicKey);
    }

    public byte[] getBytes() {
        return publicKey;
    }
}
