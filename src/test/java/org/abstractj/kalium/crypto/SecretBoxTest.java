package org.abstractj.kalium.crypto;

import org.abstractj.kalium.encoders.Hex;
import org.junit.Test;

import java.util.Arrays;

import static org.abstractj.kalium.fixture.TestVectors.BOX_CIPHERTEXT;
import static org.abstractj.kalium.fixture.TestVectors.BOX_MESSAGE;
import static org.abstractj.kalium.fixture.TestVectors.BOX_NONCE;
import static org.abstractj.kalium.fixture.TestVectors.SECRET_KEY;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class SecretBoxTest {

    @Test
    public void testAcceptStrings() throws Exception {
        try {
            new SecretBox(SECRET_KEY);
        } catch (Exception e) {
            fail("SecretBox should accept strings");
        }
    }

    @Test(expected = RuntimeException.class)
    public void testNullKey() throws Exception {
        String key = null;
        new SecretBox(key);
        fail("Should raise an exception");
    }

    @Test(expected = RuntimeException.class)
    public void testShortKey() throws Exception {
        String key = "hello";
        new SecretBox(key);
        fail("Should raise an exception");
    }

    @Test
    public void testEncrypt() throws Exception {
        SecretBox box = new SecretBox(SECRET_KEY);

        byte[] nonce = Hex.decodeHexString(BOX_NONCE);
        byte[] message = Hex.decodeHexString(BOX_MESSAGE);
        byte[] ciphertext = Hex.decodeHexString(BOX_CIPHERTEXT);

        byte[] result = box.encrypt(nonce, message);
        assertTrue("failed to generate ciphertext", Arrays.equals(result, ciphertext));
    }

    @Test
    public void testDecrypt() throws Exception {

        SecretBox box = new SecretBox(SECRET_KEY);

        byte[] nonce = Hex.decodeHexString(BOX_NONCE);
        byte[] expectedMessage = Hex.decodeHexString(BOX_MESSAGE);
        byte[] ciphertext = Hex.decodeHexString(BOX_CIPHERTEXT);

        byte[] result = box.encrypt(nonce, expectedMessage);
        byte[] message = box.decrypt(nonce, result);

        assertTrue("failed to decrypt ciphertext", Arrays.equals(message, expectedMessage));
    }

    @Test(expected = RuntimeException.class)
    public void testDecryptCorruptedCipherText() throws Exception {
        SecretBox box = new SecretBox(SECRET_KEY);
        byte[] nonce = Hex.decodeHexString(BOX_NONCE);
        byte[] message = Hex.decodeHexString(BOX_MESSAGE);
        byte[] ciphertext = box.encrypt(nonce, message);
        ciphertext[23] = ' ';

        box.decrypt(nonce, ciphertext);
        fail("Should raise an exception");
    }
}
