package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl.Sodium;
import org.abstractj.kalium.encoders.Hex;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;
import static org.abstractj.kalium.NaCl.Sodium.SHA256BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SHA512BYTES;

public class Hash {

    private static final Sodium sodium = SODIUM_INSTANCE;

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
