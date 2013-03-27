package org.abstractj.kalium.crypto;

import org.abstractj.kalium.keys.PrivateKey;
import org.abstractj.kalium.keys.PublicKey;
import org.junit.Test;

public class BoxTest {

    private Box box;

    String bobPrivate = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    String alicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

    @Test
    public void testEncrypt() throws Exception {
        PrivateKey bobKey = new PrivateKey(bobPrivate);
        PublicKey aliceKey = new PublicKey(alicePublic);
        box = new Box(bobKey, aliceKey);
        byte[] value = box.encrypt(Random.randomBytes(24), "sodium");
    }
}
