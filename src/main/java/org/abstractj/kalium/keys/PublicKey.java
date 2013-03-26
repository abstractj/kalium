package org.abstractj.kalium.keys;

import org.abstractj.kalium.util.Hex;

public class PublicKey {

    private final byte[] publicKey;

    public PublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public String toHex(){
        return Hex.encodeHexString(publicKey);
    }
}
