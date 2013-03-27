package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl.Sodium;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;

public class Random {

    private static final Sodium sodium = SODIUM_INSTANCE;

    /**
     * Generate random bytes
     *
     * @param n number or random bytes
     * @return
     */
    public static byte[] randomBytes(int n) {
        byte[] buffer = new byte[32];
        sodium.randombytes(buffer, n);
        return buffer;
    }
}
