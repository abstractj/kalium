package org.abstractj.kalium.crypto;

import org.junit.Assert;
import org.junit.Test;

public class UtilTest {
    @Test
    public void testPrependZeros() throws Exception {
        byte[] src = {'t', 'e', 's', 't'};
        byte[] result = Util.prependZeros(3, src);
        Assert.assertArrayEquals(new byte[]{0, 0, 0, 't', 'e', 's', 't'}, result);
    }
}
