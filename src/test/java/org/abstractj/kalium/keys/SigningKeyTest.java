/*
 * Copyright 2013 Bruno Oliveira, and individual contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.abstractj.kalium.keys;

import org.abstractj.kalium.encoders.Hex;
import org.junit.Test;

import java.util.Arrays;

import static org.abstractj.kalium.fixture.TestVectors.SIGN_MESSAGE;
import static org.abstractj.kalium.fixture.TestVectors.SIGN_PRIVATE;
import static org.abstractj.kalium.fixture.TestVectors.SIGN_SIGNATURE;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class SigningKeyTest {

    @Test
    public void testGenerateSigninKey() throws Exception {
        try {
            SigningKey key = new SigningKey().generate();
            assertTrue(key instanceof SigningKey);
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }

    @Test
    public void testAcceptsValidKey() throws Exception {
        try {
            SigningKey key = new SigningKey(SIGN_PRIVATE).generate();
            assertTrue(key instanceof SigningKey);
        } catch (Exception e) {
            e.printStackTrace();
            fail("Should return a valid key size");
        }
    }

    @Test
    public void testCreateHexValidKey() throws Exception {
        try {
            new SigningKey(SIGN_PRIVATE).generate().toHex();
        } catch (Exception e) {
            e.printStackTrace();
            fail("Should return a valid key size");
        }
    }

    @Test
    public void testCreateByteValidKey() throws Exception {
        try {
            new SigningKey(SIGN_PRIVATE).generate().getBytes();
        } catch (Exception e) {
            e.printStackTrace();
            fail("Should return a valid key size");
        }
    }

    @Test(expected = RuntimeException.class)
    public void testRejectNullKey() throws Exception {
        String key = null;
        new SigningKey(key);
        fail("Should reject null keys");
    }

    @Test(expected = RuntimeException.class)
    public void testRejectShortKey() throws Exception {
        String key = "short";
        new SigningKey(key);
        fail("Should reject short keys");
    }

    @Test
    public void testSignMessageAsBytes() throws Exception {
        SigningKey key = new SigningKey(SIGN_PRIVATE).generate();
        byte[] signedMessage = key.sign(Hex.decodeHexString(SIGN_MESSAGE));
        assertTrue("Message sign has failed", Arrays.equals(Hex.decodeHexString(SIGN_SIGNATURE), signedMessage));
    }
}
