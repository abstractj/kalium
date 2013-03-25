package org.abstractj.kalium.crypto;

import org.abstractj.kalium.Sodium;
import org.abstractj.kalium.Sodium.CSodium;

public class Hash {

    private static final CSodium sodium = Sodium.getInstance();

    public static byte[] sha256(String message) {
        byte[] buffer = new byte[32];
        sodium.crypto_hash_sha256_ref(buffer, message, message.length());
        return buffer;
    }

    public static byte[] sha512(String message) {
        byte[] buffer = new byte[64];
        sodium.crypto_hash_sha512_ref(buffer, message, message.length());
        return buffer;
    }

}
