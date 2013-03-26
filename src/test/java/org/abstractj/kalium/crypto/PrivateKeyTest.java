package org.abstractj.kalium.crypto;

import org.abstractj.kalium.keys.PrivateKey;
import org.junit.Test;

public class PrivateKeyTest {

    @Test
    public void testGenerate() throws Exception {
        System.out.println(PrivateKey.generate());
    }
}
