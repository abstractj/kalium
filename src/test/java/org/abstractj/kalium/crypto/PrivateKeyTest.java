package org.abstractj.kalium.crypto;

import org.abstractj.kalium.keys.PrivateKey;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class PrivateKeyTest {

    @Test
    public void testGenerate() throws Exception {
        PrivateKey key = PrivateKey.generate();
        assertEquals("Invalid private key size", 32, key.getBytes().length);
        assertEquals("Invalid public key size", 32, key.getPublicKey().getBytes().length);
    }
}
