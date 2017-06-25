/**
 * Copyright 2017 Bruno Oliveira, and individual contributors
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

import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.SIPHASH24_KEY;
import static org.abstractj.kalium.fixture.TestVectors.SIPHASH24_MESSAGE;
import static org.abstractj.kalium.fixture.TestVectors.SIPHASH24_DIGEST;
import static org.abstractj.kalium.fixture.TestVectors.SIPHASH24_DIGEST_EMPTY_STRING;

import static org.junit.Assert.assertEquals;

public class ShortHashTest {

    private final ShortHash hash = new ShortHash();

    @Test
    public void testSiphash24() throws Exception {
        byte[] message = HEX.decode(SIPHASH24_MESSAGE);
        byte[] key = HEX.decode(SIPHASH24_KEY);
        String result = HEX.encode(hash.siphash24(message, key));
        assertEquals("Hash is invalid", SIPHASH24_DIGEST, result);
    }

    @Test
    public void testSiphash24EmptyString() throws Exception {
        byte[] key = HEX.decode(SIPHASH24_KEY);
        String result = HEX.encode(hash.siphash24(new byte[0], key));
        assertEquals("Hash is invalid", SIPHASH24_DIGEST_EMPTY_STRING, result);
    }

    @Test(expected = RuntimeException.class)
    public void testSiphash24InvalidKey() throws Exception {
        byte[] message = HEX.decode(SIPHASH24_MESSAGE);
        byte[] invalidKey = new byte[1];
        hash.siphash24(message, invalidKey);
    }
}
