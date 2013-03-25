package org.abstractj.kalium.crypto;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class HashTest {

    private Hash hash = new Hash();

    @Test
    public void testSha256() throws Exception {
        String expected = "ee9d62778c8b664aa8501af83ec4738e01d20f2cdca133208c7bf66cbcaa37b8";
        String result = hash.sha256("sodium").toHex();
        assertEquals("Hash value must be the same", expected, result);
    }

    @Test
    public void testSha512() throws Exception {
        String expected = "961b4af816284b41547aaff17bef5eae144f4a29dafa7b1819100e0e8deb93bea" +
                "53946b38c579ba6a74162f3bdbc5adc672d4ec52425971d3072c37e18430fc0";
        String result = hash.sha512("sodium").toHex();
        assertEquals("Hash value must be the same", expected, result);
    }
}
