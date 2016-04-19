/**
 * Copyright 2013 Bruno Oliveira, and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.abstractj.kalium.crypto;

import org.junit.Test;

import java.util.Arrays;

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_SECRETBOX_MACBYTES;
import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.*;
import static org.junit.Assert.*;

public class SecretBoxTest {

    @Test
    public void testAcceptStrings() throws Exception {
        try {
            new SecretBox(SECRET_KEY, HEX);
        } catch (Exception e) {
            fail("SecretBox should accept strings");
        }
    }

    @Test(expected = RuntimeException.class)
    public void testNullKey() throws Exception {
        byte[] key = null;
        new SecretBox(key);
        fail("Should raise an exception");
    }

    @Test(expected = RuntimeException.class)
    public void testShortKey() throws Exception {
        String key = "hello";
        new SecretBox(key.getBytes());
        fail("Should raise an exception");
    }

    @Test
    public void testEncrypt() throws Exception {
        SecretBox box = new SecretBox(SECRET_KEY, HEX);

        byte[] nonce = HEX.decode(BOX_NONCE);
        byte[] message = HEX.decode(BOX_MESSAGE);
        byte[] ciphertext = HEX.decode(BOX_CIPHERTEXT);

        byte[] result = box.encrypt(nonce, message);
        assertTrue("failed to generate ciphertext", Arrays.equals(result, ciphertext));
    }

    @Test
    public void testEncryptDetached() throws Exception {
        SecretBox box = new SecretBox(SECRET_KEY, HEX);

        byte[] nonce = HEX.decode(BOX_NONCE);
        byte[] message = HEX.decode(BOX_MESSAGE);
        byte[] ciphertext = new byte[message.length];
        byte[] mac = new byte[CRYPTO_SECRETBOX_MACBYTES];
        System.arraycopy(HEX.decode(BOX_CIPHERTEXT), CRYPTO_SECRETBOX_MACBYTES, ciphertext, 0, message.length);
        System.arraycopy(HEX.decode(BOX_CIPHERTEXT), 0, mac, 0, CRYPTO_SECRETBOX_MACBYTES);

        byte[][] result = box.encryptDetached(nonce, message);

        assertArrayEquals("failed to generate ciphertext", ciphertext, result[0]);
        assertArrayEquals("failed to generate mac", mac, result[1]);
    }

    @Test
    public void testDecrypt() throws Exception {

        SecretBox box = new SecretBox(SECRET_KEY, HEX);

        byte[] nonce = HEX.decode(BOX_NONCE);
        byte[] expectedMessage = HEX.decode(BOX_MESSAGE);
        byte[] ciphertext = box.encrypt(nonce, expectedMessage);

        byte[] message = box.decrypt(nonce, ciphertext);

        assertTrue("failed to decrypt ciphertext", Arrays.equals(message, expectedMessage));
    }

    @Test
    public void testDecryptDetached() throws Exception {

        SecretBox box = new SecretBox(SECRET_KEY, HEX);

        byte[] nonce = HEX.decode(BOX_NONCE);
        byte[] expectedMessage = HEX.decode(BOX_MESSAGE);
        byte[] ciphertext = new byte[expectedMessage.length];
        byte[] mac = new byte[CRYPTO_SECRETBOX_MACBYTES];
        System.arraycopy(HEX.decode(BOX_CIPHERTEXT), CRYPTO_SECRETBOX_MACBYTES, ciphertext, 0, expectedMessage.length);
        System.arraycopy(HEX.decode(BOX_CIPHERTEXT), 0, mac, 0, CRYPTO_SECRETBOX_MACBYTES);

        byte[] message = box.decryptDetached(nonce, ciphertext, mac);

        assertTrue("failed to decrypt ciphertext", Arrays.equals(message, expectedMessage));
    }

    @Test(expected = RuntimeException.class)
    public void testDecryptCorruptedCipherText() throws Exception {
        SecretBox box = new SecretBox(SECRET_KEY, HEX);
        byte[] nonce = HEX.decode(BOX_NONCE);
        byte[] message = HEX.decode(BOX_MESSAGE);
        byte[] ciphertext = box.encrypt(nonce, message);
        ciphertext[23] = ' ';

        box.decrypt(nonce, ciphertext);
        fail("Should raise an exception");
    }
}
