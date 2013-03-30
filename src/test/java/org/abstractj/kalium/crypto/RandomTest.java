package org.abstractj.kalium.crypto;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class RandomTest {

    @Test
    public void testProducesRandomBytes() throws Exception {
        final int size = 16;
        assertEquals("Invalid random bytes", size, Random.randomBytes(size).length);
    }

    @Test
    public void testProducesDefaultRandomBytes() throws Exception {
        final int size = 32;
        assertEquals("Invalid random bytes", size, Random.randomBytes().length);
    }

    @Test
    public void testProducesDifferentRandomBytes() throws Exception {
        final int size = 16;
        assertFalse("Should produce different random bytes", Arrays.equals(Random.randomBytes(size), Random.randomBytes(size)));
    }

    @Test
    public void testProducesDifferentDefaultRandomBytes() throws Exception {
        final int size = 32;
        assertFalse("Should produce different random bytes", Arrays.equals(Random.randomBytes(), Random.randomBytes(size)));
    }
}
