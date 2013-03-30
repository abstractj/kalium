package org.abstractj.kalium.crypto;

import org.abstractj.kalium.encoders.Hex;
import org.abstractj.kalium.keys.PrivateKey;
import org.abstractj.kalium.keys.PublicKey;
import org.junit.Test;

import java.util.Arrays;

import static org.abstractj.kalium.fixture.TestVectors.ALICE_PRIVATE_KEY;
import static org.abstractj.kalium.fixture.TestVectors.ALICE_PUBLIC_KEY;
import static org.abstractj.kalium.fixture.TestVectors.BOB_PRIVATE_KEY;
import static org.abstractj.kalium.fixture.TestVectors.BOB_PUBLIC_KEY;
import static org.abstractj.kalium.fixture.TestVectors.BOX_CIPHERTEXT;
import static org.abstractj.kalium.fixture.TestVectors.BOX_MESSAGE;
import static org.abstractj.kalium.fixture.TestVectors.BOX_NONCE;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


public class BoxTest {

    @Test
    public void testAcceptStrings() throws Exception {
        try {
            new Box(ALICE_PUBLIC_KEY, BOB_PRIVATE_KEY);
        } catch (Exception e) {
            fail("Box should accept strings");
        }
    }

    @Test
    public void testAcceptKeyPairs() throws Exception {
        try {
            new Box(new PublicKey(ALICE_PUBLIC_KEY), new PrivateKey(BOB_PRIVATE_KEY));
        } catch (Exception e) {
            fail("Box should accept key pairs");
        }
    }

    @Test(expected = RuntimeException.class)
    public void testNullPublicKey() throws Exception {
        String key = null;
        new Box(new PublicKey(key), new PrivateKey(BOB_PRIVATE_KEY));
        fail("Should raise an exception");
    }

    @Test(expected = RuntimeException.class)
    public void testInvalidPublicKey() throws Exception {
        String key = "hello";
        new Box(new PublicKey(key), new PrivateKey(BOB_PRIVATE_KEY));
        fail("Should raise an exception");
    }

    @Test(expected = RuntimeException.class)
    public void testNullSecretKey() throws Exception {
        String key = null;
        new Box(new PublicKey(ALICE_PUBLIC_KEY), new PrivateKey(key));
        fail("Should raise an exception");
    }

    @Test(expected = RuntimeException.class)
    public void testInvalidSecretKey() throws Exception {
        String key = "hello";
        new Box(new PublicKey(ALICE_PUBLIC_KEY), new PrivateKey(key));
        fail("Should raise an exception");
    }

    @Test
    public void testEncrypt() throws Exception {
        Box box = new Box(new PublicKey(ALICE_PUBLIC_KEY), new PrivateKey(BOB_PRIVATE_KEY));
        byte[] nonce = Hex.decodeHexString(BOX_NONCE);
        byte[] message = Hex.decodeHexString(BOX_MESSAGE);
        byte[] ciphertext = Hex.decodeHexString(BOX_CIPHERTEXT);

        byte[] result = box.encrypt(nonce, message);
        assertTrue("failed to generate ciphertext", Arrays.equals(result, ciphertext));
    }

    @Test
    public void testDecrypt() throws Exception {
        Box box = new Box(new PublicKey(ALICE_PUBLIC_KEY), new PrivateKey(BOB_PRIVATE_KEY));
        byte[] nonce = Hex.decodeHexString(BOX_NONCE);
        byte[] expectedMessage = Hex.decodeHexString(BOX_MESSAGE);
        byte[] ciphertext = box.encrypt(nonce, expectedMessage);

        Box pandora = new Box(new PublicKey(BOB_PUBLIC_KEY), new PrivateKey(ALICE_PRIVATE_KEY));
        byte[] message = pandora.decrypt(nonce, ciphertext);
        assertTrue("failed to decrypt ciphertext", Arrays.equals(message, expectedMessage));
    }

    @Test(expected = RuntimeException.class)
    public void testDecryptCorruptedCipherText() throws Exception {
        Box box = new Box(new PublicKey(ALICE_PUBLIC_KEY), new PrivateKey(BOB_PRIVATE_KEY));
        byte[] nonce = Hex.decodeHexString(BOX_NONCE);
        byte[] expectedMessage = Hex.decodeHexString(BOX_MESSAGE);
        byte[] ciphertext = box.encrypt(nonce, expectedMessage);
        ciphertext[23] = ' ';

        Box pandora = new Box(new PublicKey(BOB_PUBLIC_KEY), new PrivateKey(ALICE_PRIVATE_KEY));
        pandora.decrypt(nonce, ciphertext);
        fail("Should raise an exception");
    }
}
