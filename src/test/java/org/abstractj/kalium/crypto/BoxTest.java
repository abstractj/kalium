package org.abstractj.kalium.crypto;

import org.abstractj.kalium.keys.PrivateKey;
import org.junit.Test;

public class BoxTest {

    private Box box;

    @Test
    public void testEncrypt() throws Exception {
        PrivateKey key = PrivateKey.generate();
        box = new Box(key, key.getPublicKey());
        System.out.println("Test: " + box.encrypt(Random.randomBytes(32), "meh"));
    }
}
