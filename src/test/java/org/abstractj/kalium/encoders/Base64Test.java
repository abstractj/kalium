package org.abstractj.kalium.encoders;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

public class Base64Test {

    private Encoder encoder;

    @Before
    public void setUp() {
        encoder = new Base64();
    }

    @Test
    public void testEncode() throws Exception {
        String value = "hello";
        String expected = "aGVsbG8=";
        assertEquals(expected, encoder.encode(value.getBytes()));
    }

    @Test
    public void testEncodeNullString() throws Exception {
        byte[] value = null;
        try {
            assertNull(encoder.encode(value));
        } catch (Exception e) {
            fail("Should not raise any exception");
        }
    }

    @Test
    public void testEncodeEmptyString() throws Exception {
        byte[] value = new byte[0];
        try {
            assertEquals("",encoder.encode(value));
        } catch (Exception e) {
            fail("Should not raise any exception");
        }
    }

    @Test
    public void testDecode() throws Exception {
        String value = "aGVsbG8=";
        String expected = "hello";
        assertEquals(expected,new String(encoder.decode(value)));
    }

    @Test
    public void testDecodeNoPadding() throws Exception {
        String value = "aGVsbG8";
        String expected = "hello";
        assertEquals(expected,new String(encoder.decode(value)));
    }

    @Test
    public void testDecodeExtraPadding() throws Exception {
        String value = "aGVsbG8===";
        String expected = "hello";
        assertEquals(expected,new String(encoder.decode(value)));
    }

    @Test
    public void testDecodeAllPadding() throws Exception {
        String value = "=======";
        assertTrue(Arrays.equals(encoder.decode(value),new byte[0]));
    }

    @Test
    public void testDecodeEmptyString() throws Exception {
        String value = "";
        assertTrue(Arrays.equals(encoder.decode(value),new byte[0]));
    }

    @Test
    public void testDecodeNullString() throws Exception {
        String value = null;
        try {
            assertTrue(Arrays.equals(encoder.decode(value),new byte[0]));
        } catch (Exception e) {
            e.printStackTrace();
            fail("Should not raise any exception");
        }
    }
}
