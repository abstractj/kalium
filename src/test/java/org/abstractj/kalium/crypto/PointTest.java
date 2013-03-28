package org.abstractj.kalium.crypto;

import org.junit.Test;

import static org.abstractj.kalium.fixture.TestVectors.ALICE_MULT_BOB;
import static org.abstractj.kalium.fixture.TestVectors.ALICE_PRIVATE_KEY;
import static org.abstractj.kalium.fixture.TestVectors.ALICE_PUBLIC_KEY;
import static org.abstractj.kalium.fixture.TestVectors.BOB_PUBLIC_KEY;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class PointTest {

    @Test
    public void testMultipleIntegersWithBasePoint() throws Exception {
        Point point = new Point();
        String mult = point.mult(ALICE_PRIVATE_KEY).toHex();
        assertEquals("Should return a serialized point", ALICE_PUBLIC_KEY, mult);
    }

    @Test
    public void testMultipleIntegersWithArbitraryPoints() throws Exception {
        Point point = new Point(BOB_PUBLIC_KEY);
        String mult = point.mult(ALICE_PRIVATE_KEY).toHex();
        assertEquals("Should return a valid serialized point", ALICE_MULT_BOB, mult);
    }

    @Test
    public void testSerializeToBytes() throws Exception {
        fail("To be implemented");
    }

    @Test
    public void testSerializeToHex() throws Exception {
        fail("To be implemented");
    }
}
