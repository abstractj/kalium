package org.abstractj.kalium.crypto;

import org.abstractj.kalium.encoders.Hex;
import org.junit.Test;

import static org.abstractj.kalium.fixture.TestVectors.ALICE_MULT_BOB;
import static org.abstractj.kalium.fixture.TestVectors.ALICE_PRIVATE_KEY;
import static org.abstractj.kalium.fixture.TestVectors.ALICE_PUBLIC_KEY;
import static org.abstractj.kalium.fixture.TestVectors.BOB_PUBLIC_KEY;
import static org.junit.Assert.assertEquals;

public class PointTest {

    @Test
    public void testMultipleIntegersWithBasePoint() throws Exception {
        Point point = new Point();
        String mult = point.mult(ALICE_PRIVATE_KEY).value();
        assertEquals("Should return a serialized point", ALICE_PUBLIC_KEY, mult);
    }

    @Test
    public void testMultipleIntegersWithArbitraryPoints() throws Exception {
        Point point = new Point(BOB_PUBLIC_KEY);
        String mult = point.mult(ALICE_PRIVATE_KEY).value();
        assertEquals("Should return a valid serialized point", ALICE_MULT_BOB, mult);
    }

    @Test
    public void testSerializeToBytes() throws Exception {
        Point point = new Point(BOB_PUBLIC_KEY);
        assertEquals("Should serialize to bytes", BOB_PUBLIC_KEY, Hex.encodeHexString(point.toBytes()));
    }

    @Test
    public void testSerializeToHex() throws Exception {
        Point point = new Point(BOB_PUBLIC_KEY);
        assertEquals("Should serialize to hex", BOB_PUBLIC_KEY, point.toHex());
    }
}
