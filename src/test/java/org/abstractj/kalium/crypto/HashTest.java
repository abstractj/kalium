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
