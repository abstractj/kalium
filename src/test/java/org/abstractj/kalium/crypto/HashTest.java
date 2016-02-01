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

import org.abstractj.kalium.NaCl;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.isValid;
import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.*;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;

public class HashTest {

    private final Hash hash = new Hash();

    @Test
    public void testSha256() throws Exception {
        final byte[] rawMessage = SHA256_MESSAGE.getBytes();
        String result = HEX.encode(hash.sha256(rawMessage));
        assertTrue("Hash is invalid", Arrays.equals(SHA256_DIGEST.getBytes(), result.getBytes()));
    }

    @Test
    public void testSha256EmptyString() throws Exception {
        byte[] result = hash.sha256("".getBytes());
        assertEquals("Hash is invalid", SHA256_DIGEST_EMPTY_STRING, HEX.encode(result));
    }

    @Test
    public void testSha256HexString() throws Exception {
        String result = hash.sha256(SHA256_MESSAGE, HEX);
        assertEquals("Hash is invalid", SHA256_DIGEST, result);
    }

    @Test
    public void testSha256EmptyHexString() throws Exception {
        String result = hash.sha256("", HEX);
        assertEquals("Hash is invalid", SHA256_DIGEST_EMPTY_STRING, result);
    }

    @Test
    public void testSha256NullByte() {
        try {
            hash.sha256("\0".getBytes());
        } catch (Exception e) {
            fail("Should not raise any exception on null byte");
        }
    }

    @Test
    public void testSha256Interactive() throws Exception {
        Hash.MultiPartHash sha256 = hash.sha256();
        sha256.init();
        sha256.update(SHA256_MESSAGE.getBytes());
        byte[] out = sha256.done();
        assertArrayEquals(SHA256_DIGEST.getBytes(), HEX.encode(out).getBytes());
    }

    @Test
    public void testSha512() throws Exception {
        final byte[] rawMessage = SHA512_MESSAGE.getBytes();
        String result = HEX.encode(hash.sha512(rawMessage));
        assertTrue("Hash is invalid", Arrays.equals(SHA512_DIGEST.getBytes(), result.getBytes()));
    }

    @Test
    public void testSha512EmptyString() throws Exception {
        byte[] result = hash.sha512("".getBytes());
        assertEquals("Hash is invalid", SHA512_DIGEST_EMPTY_STRING, HEX.encode(result));
    }

    @Test
    public void testSha512HexString() throws Exception {
        String result = hash.sha512(SHA512_MESSAGE, HEX);
        assertEquals("Hash is invalid", SHA512_DIGEST, result);
    }

    @Test
    public void testSha512EmptyHexString() throws Exception {
        String result = hash.sha512("", HEX);
        assertEquals("Hash is invalid", SHA512_DIGEST_EMPTY_STRING, result);
    }

    @Test
    public void testSha512NullByte() {
        try {
            hash.sha512("\0".getBytes());
        } catch (Exception e) {
            fail("Should not raise any exception on null byte");
        }
    }

    @Test
    public void testSha512Interactive() throws Exception {
        Hash.MultiPartHash sha512 = hash.sha512();
        sha512.init();
        sha512.update(SHA512_MESSAGE.getBytes());
        byte[] out = sha512.done();
        assertArrayEquals(SHA512_DIGEST.getBytes(), HEX.encode(out).getBytes());
    }

    @Test
    public void testBlake2() throws Exception {
        final byte[] rawMessage = Blake2_MESSAGE.getBytes();
        String result = HEX.encode(hash.blake2(rawMessage));
        assertTrue("Hash is invalid", Arrays.equals(Blake2_DIGEST.getBytes(), result.getBytes()));
    }

    @Test
    public void testBlake2EmptyString() throws Exception {
        byte[] result = hash.blake2("".getBytes());
        assertEquals("Hash is invalid", Blake2_DIGEST_EMPTY_STRING, HEX.encode(result));
    }

    @Test
    public void testBlake2HexString() throws Exception {
        String result = hash.blake2(Blake2_MESSAGE, HEX);
        assertEquals("Hash is invalid", Blake2_DIGEST, result);
    }

    @Test
    public void testBlake2EmptyHexString() throws Exception {
        String result = hash.blake2("", HEX);
        assertEquals("Hash is invalid", Blake2_DIGEST_EMPTY_STRING, result);
    }

    @Test
    public void testBlake2NullByte() {
        try {
            hash.blake2("\0".getBytes());
        } catch (Exception e) {
            fail("Should not raise any exception on null byte");
        }
    }

    @Test
    public void testBlake2WithSaltAndPersonal() {
        byte[] result = hash.blake2(Blake2_MESSAGE.getBytes(), Blake2_KEY.getBytes(),
                Blake2_SALT.getBytes(),
                Blake2_PERSONAL.getBytes());
        assertEquals("Hash is invalid", Blake2_DIGEST_WITH_SALT_PERSONAL, HEX.encode(result));
    }

    @Test
    public void testBlakeInteractive() throws Exception {
        byte[] state = new byte[sodium().crypto_generichash_statebytes()];
        isValid(sodium().crypto_generichash_init(
                        state, null, 0, NaCl.Sodium.CRYPTO_GENERICHASH_BYTES_MAX),
                "init failed");

        byte[] msg = Blake2_MESSAGE.getBytes();
        isValid(sodium().crypto_generichash_update(
                        state, msg, msg.length),
                "update failed");

        byte[] out = new byte[NaCl.Sodium.CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX];
        isValid(sodium().crypto_generichash_final(
                        state, out, out.length),
                "final failed");

        assertArrayEquals(HEX.decode(Blake2_DIGEST), out);
    }

    @Test
    public void testShortHash() throws Exception {
        byte[] key = HEX.decode(SHORTHASH_KEY);
        for(int i = 0; i < SHORTHASH_MESSAGES.length; i++) {
            byte[] msg = HEX.decode(SHORTHASH_MESSAGES[i]);
            byte[] result = hash.shortHash(msg, key);
            assertEquals(SHORTHASH_HASHES[i], HEX.encode(result));
        }
    }
}
