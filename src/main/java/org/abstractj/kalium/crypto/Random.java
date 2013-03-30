package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl.Sodium;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;

public class Random {

    private static final Sodium sodium = SODIUM_INSTANCE;
    private static final int DEFAULT_SIZE = 32;

    /**
     * Generate random bytes
     *
     * @param n number or random bytes
     * @return
     */
    public static byte[] randomBytes(int n) {
        byte[] buffer = new byte[n];
        sodium.randombytes(buffer, n);
        return buffer;
    }

    public static byte[] randomBytes() {
        byte[] buffer = new byte[DEFAULT_SIZE];
        sodium.randombytes(buffer, DEFAULT_SIZE);
        return buffer;
    }
}
