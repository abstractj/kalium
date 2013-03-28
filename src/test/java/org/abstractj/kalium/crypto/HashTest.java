package org.abstractj.kalium.crypto;

import org.junit.Test;

import static org.abstractj.kalium.fixture.TestVectors.SHA256_DIGEST;
import static org.abstractj.kalium.fixture.TestVectors.SHA256_DIGEST_EMPTY_STRING;
import static org.abstractj.kalium.fixture.TestVectors.SHA256_MESSAGE;
import static org.abstractj.kalium.fixture.TestVectors.SHA512_DIGEST;
import static org.abstractj.kalium.fixture.TestVectors.SHA512_DIGEST_EMPTY_STRING;
import static org.abstractj.kalium.fixture.TestVectors.SHA512_MESSAGE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class HashTest {

    private Hash hash = new Hash();

    @Test
    public void testSha256() throws Exception {
        String result = hash.sha256(SHA256_MESSAGE).toHex();
        assertEquals("Hash is invalid", SHA256_DIGEST, result);
    }

    @Test
    public void testSha256EmptyString() throws Exception {
        String result = hash.sha256("").toHex();
        assertEquals("Hash is invalid", SHA256_DIGEST_EMPTY_STRING, result);
    }

    @Test
    public void testSha256NullByte() {
        try {
            hash.sha256("\0").toHex();
        } catch (Exception e) {
            fail("Should not raise any exception on null byte");
        }
    }

    @Test
    public void testSha512() throws Exception {
        String result = hash.sha512(SHA512_MESSAGE).toHex();
        assertEquals("Hash value must be the same", SHA512_DIGEST, result);
    }

    @Test
    public void testSha512EmptyString() throws Exception {
        String result = hash.sha512("").toHex();
        assertEquals("Hash is invalid", SHA512_DIGEST_EMPTY_STRING, result);
    }

    @Test
    public void testSha512NullByte() {
        try {
            hash.sha512("\0").toHex();
        } catch (Exception e) {
            fail("Should not raise any exception on null byte");
        }
    }
}
