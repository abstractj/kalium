package org.abstractj.kalium.crypto;

import org.abstractj.kalium.encoders.Hex;
import org.abstractj.kalium.keys.PrivateKey;
import org.abstractj.kalium.keys.PublicKey;
import org.junit.Test;

import static org.abstractj.kalium.fixture.TestVectors.ALICE_PUBLIC_KEY;
import static org.abstractj.kalium.fixture.TestVectors.BOB_PRIVATE_KEY;
import static org.junit.Assert.fail;


public class BoxTest {

    @Test
    public void testAcceptStrings() throws Exception {
        try {
            new Box(ALICE_PUBLIC_KEY, BOB_PRIVATE_KEY);
        } catch (Exception e) {
            fail("Box should accept strings");
        }
    }

    @Test
    public void testAcceptKeyPairs() throws Exception {
        try {
            new Box(new PublicKey(ALICE_PUBLIC_KEY), new PrivateKey(BOB_PRIVATE_KEY));
        } catch (Exception e) {
            fail("Box should accept key pairs");
        }
    }

    @Test(expected = RuntimeException.class)
    public void testNullPublicKey() throws Exception {
        String key = null;
        new Box(new PublicKey(key), new PrivateKey(BOB_PRIVATE_KEY));
        fail("Should raise an exception");
    }

    @Test(expected = RuntimeException.class)
    public void testInvalidPublicKey() throws Exception {
        String key = "hello";
        new Box(new PublicKey(key), new PrivateKey(BOB_PRIVATE_KEY));
        fail("Should raise an exception");
    }

    @Test(expected = RuntimeException.class)
    public void testNullSecretKey() throws Exception {
        String key = null;
        new Box(new PublicKey(ALICE_PUBLIC_KEY), new PrivateKey(key));
        fail("Should raise an exception");
    }

    @Test(expected = RuntimeException.class)
    public void testInvalidSecretKey() throws Exception {
        String key = "hello";
        new Box(new PublicKey(ALICE_PUBLIC_KEY), new PrivateKey(key));
        fail("Should raise an exception");
    }
}
