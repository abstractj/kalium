package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl;
import org.junit.Test;

import static org.junit.Assert.assertTrue;
import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.*;
import static org.abstractj.kalium.fixture.TestVectors.PWHASH_MESSAGE;
import static org.abstractj.kalium.fixture.TestVectors.PWHASH_SALT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Created by abstractj on 8/5/15.
 */
public class PasswordTest {

    private final Password password = new Password();

    @Test
    public void testPWHash(){
        String result = password.hash(PWHASH_MESSAGE.getBytes(),
                HEX,
                PWHASH_SALT.getBytes(),
                NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);
        assertEquals("Hash is invalid", PWHASH_DIGEST, result);
    }

    @Test
    public void testPWHashEmptyString(){
        String result = password.hash("".getBytes(),
                HEX,
                PWHASH_SALT.getBytes(),
                NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);
        assertEquals("Hash is invalid", PWHASH_DIGEST_EMPTY_STRING, result);
    }

    @Test
    public void testPWHashNullByte() {
        try {
            password.hash("\0".getBytes(),
                    HEX,
                    PWHASH_SALT.getBytes(),
                    NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                    NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);
        } catch (Exception e) {
            fail("Should not raise any exception on null byte");
        }
    }

    @Test
    public void testPWHashStorage(){
        String result = password.hash(PWHASH_MESSAGE.getBytes(),
                HEX,
                NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);
        byte[] hashed = HEX.decode(result);

        // Must return true
        boolean verified1 = password.verify(hashed, PWHASH_MESSAGE.getBytes());
        assertTrue("Invalid password", verified1);

        // Must return false since it's an invalid
        boolean verified2 = password.verify(hashed, ("i" + PWHASH_MESSAGE).getBytes());
        assertTrue("Valid password", !verified2);
    }

    @Test
    public void testPWHashKeyDerivation() {
        String result = password.hash(NaCl.Sodium.XSALSA20_POLY1305_SECRETBOX_KEYBYTES,
                PWHASH_MESSAGE.getBytes(),
                HEX,
                PWHASH_SALT.getBytes(),
                NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);
        byte[] hashed = HEX.decode(result);

        // Must receive expected size
        assertEquals(NaCl.Sodium.XSALSA20_POLY1305_SECRETBOX_KEYBYTES, hashed.length);
    }

    @Test
    public void testPWHashKeyDerivationBytes() {
        byte[] key = password.deriveKey(NaCl.Sodium.XSALSA20_POLY1305_SECRETBOX_KEYBYTES,
                PWHASH_MESSAGE.getBytes(),
                PWHASH_SALT.getBytes(),
                NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
                NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);

        // Must receive expected size
        assertEquals(NaCl.Sodium.XSALSA20_POLY1305_SECRETBOX_KEYBYTES, key.length);
    }
}
