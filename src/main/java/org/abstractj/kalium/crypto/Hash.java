package org.abstractj.kalium.crypto;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;
import org.abstractj.kalium.util.Hex;
import org.abstractj.kalium.NaCl.Sodium;

public class Hash {

    public static final int SHA256BYTES = 32;
    public static final int SHA512BYTES = 64;

    private final Sodium sodium = SODIUM_INSTANCE;

    private static byte[] buffer;

    public Hash sha256(String message) {
        buffer = new byte[SHA256BYTES];
        sodium.crypto_hash_sha256_ref(buffer, message, message.length());
        return this;
    }

    public Hash sha512(String message) {
        buffer = new byte[SHA512BYTES];
        sodium.crypto_hash_sha512_ref(buffer, message, message.length());
        return this;
    }

    public String toHex() {
        return Hex.encodeHexString(buffer);
    }
}
