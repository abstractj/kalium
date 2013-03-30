package org.abstractj.kalium.crypto;

import org.abstractj.kalium.keys.PrivateKey;
import org.abstractj.kalium.keys.PublicKey;
import org.junit.Test;

import static org.abstractj.kalium.fixture.TestVectors.BOB_PRIVATE_KEY;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class PrivateKeyTest {

    @Test
    public void testGeneratePrivateKey() {
        try {
            PrivateKey key = PrivateKey.generate();
            assertTrue(key instanceof PrivateKey);
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }

    @Test
    public void testAcceptsValidKey() {
        try {
            new PrivateKey(BOB_PRIVATE_KEY);
        } catch (Exception e) {
            fail("Should not raise any exception");
        }
    }

    @Test
    public void testCreateHexValidKey() {
        try {
            new PrivateKey(BOB_PRIVATE_KEY).toHex();
        } catch (Exception e) {
            fail("Should not raise any exception");
        }
    }

    @Test(expected = RuntimeException.class)
    public void testRejectNullKey() throws Exception {
        String key = null;
        new PrivateKey(key);
        fail("Should reject null keys");
    }

    @Test(expected = RuntimeException.class)
    public void testRejectShortKey() throws Exception {
        String key = "short";
        new PrivateKey(key);
        fail("Should reject null keys");
    }

    @Test
    public void testGeneratePublicKey() throws Exception {
        try {
            PrivateKey key = new PrivateKey(BOB_PRIVATE_KEY);
            assertTrue(key.getPublicKey() instanceof PublicKey);
            key.getPublicKey().getBytes();
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }
}
