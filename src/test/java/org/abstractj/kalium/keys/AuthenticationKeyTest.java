/**
 * Copyright 2015 Cisco Systems, Inc.
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

package org.abstractj.kalium.keys;

import org.junit.Test;

import java.util.Arrays;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;
import static org.abstractj.kalium.NaCl.Sodium.HMACSHA512256_KEYBYTES;
import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.AUTH_HMAC_SHA512256;
import static org.abstractj.kalium.fixture.TestVectors.AUTH_KEY;
import static org.abstractj.kalium.fixture.TestVectors.AUTH_MESSAGE;
import static org.junit.Assert.fail;

public class AuthenticationKeyTest {

    @Test
    public void testAcceptsValidKey() {
        try {
            byte[] rawKey = HEX.decode(AUTH_KEY);
            new AuthenticationKey(rawKey);
        } catch (Exception e) {
            fail("Should not raise any exception");
        }
    }

    @Test
    public void testAcceptsHexEncodedKey() {
        try {
            new AuthenticationKey(AUTH_KEY, HEX);
        } catch (Exception e) {
            fail("Should not raise any exception");
        }
    }

    @Test(expected = RuntimeException.class)
    public void testRejectNullKey() throws Exception {
        byte[] key = null;
        new AuthenticationKey(key);
        fail("Should reject null keys");
    }

    @Test(expected = RuntimeException.class)
    public void testRejectShortKey() throws Exception {
        byte[] key = "short".getBytes();
        new AuthenticationKey(key);
        fail("Should reject short keys");
    }

    @Test(expected = RuntimeException.class)
    public void testRejectLongKey() throws Exception {
        byte[] key = new byte[HMACSHA512256_KEYBYTES + 1];
        new AuthenticationKey(key);
        fail("Should reject long keys");
    }

    @Test
    public void testSerializesToHex() throws Exception {
        try {
            AuthenticationKey key = new AuthenticationKey(AUTH_KEY, HEX);
            assertEquals("Correct auth key expected", AUTH_KEY, key.toString());
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }

    @Test
    public void testSerializesToBytes() throws Exception {
        try {
            AuthenticationKey key = new AuthenticationKey(AUTH_KEY, HEX);
            assertTrue("Correct auth key expected", Arrays.equals(HEX.decode(AUTH_KEY), key.toBytes()));
        } catch (Exception e) {
            fail("Should return a valid key size");
        }
    }

    @Test
    public void testSignMessageAsBytes() throws Exception {
        byte[] rawKey = HEX.decode(AUTH_KEY);
        AuthenticationKey key = new AuthenticationKey(rawKey);
        byte[] mac = key.sign(HEX.decode(AUTH_MESSAGE));
        assertTrue("Message sign has failed", Arrays.equals(HEX.decode(AUTH_HMAC_SHA512256), mac));
    }

    @Test
    public void testSignMessageAsHex() throws Exception {
        AuthenticationKey key = new AuthenticationKey(AUTH_KEY, HEX);
        String mac = key.sign(AUTH_MESSAGE, HEX);
        assertEquals("Message sign has failed", AUTH_HMAC_SHA512256, mac);
    }

    @Test
    public void testVerifyCorrectRawSignature() throws Exception {
        byte[] rawSignature = HEX.decode(AUTH_HMAC_SHA512256);
        byte[] rawMessage = HEX.decode(AUTH_MESSAGE);
        byte[] rawKey = HEX.decode(AUTH_KEY);
        AuthenticationKey authKey = new AuthenticationKey(rawKey);
        assertTrue(authKey.verify(rawMessage, rawSignature));
    }

    @Test
    public void testVerifyCorrectHexSignature() throws Exception {
        AuthenticationKey authKey = new AuthenticationKey(AUTH_KEY, HEX);
        assertTrue(authKey.verify(AUTH_MESSAGE, AUTH_HMAC_SHA512256, HEX));
    }

    @Test
    public void testDetectBadSignature() throws Exception {
        try {
            byte[] rawSignature = HEX.decode(AUTH_HMAC_SHA512256);
            byte[] rawMessage = HEX.decode(AUTH_MESSAGE);
            byte[] rawKey = HEX.decode(AUTH_KEY);
            AuthenticationKey authKey = new AuthenticationKey(rawKey);
            rawMessage[0] += 1;
            authKey.verify(rawMessage, rawSignature);
            fail("Should an exception on bad signatures");
        } catch (Exception e) {
            assertTrue(true);
        }
    }

}
