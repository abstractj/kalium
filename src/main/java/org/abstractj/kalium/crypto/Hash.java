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

import org.abstractj.kalium.NaCl.Sodium;
import org.abstractj.kalium.encoders.Hex;

import static org.abstractj.kalium.NaCl.SODIUM_INSTANCE;
import static org.abstractj.kalium.NaCl.Sodium.SHA256BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SHA512BYTES;

public class Hash {

    private static final Sodium sodium = SODIUM_INSTANCE;

    private static byte[] buffer;

    public Hash sha256(String message) {
        buffer = new byte[SHA256BYTES];
        sodium.crypto_hash_sha256_ref(buffer, message, message.length());
        return this;
    }

    public Hash sha512(String message) {
        buffer = new byte[SHA512BYTES];
        sodium.crypto_hash_sha512_ref(buffer, message, message.length());
        return this;
    }

    public String toHex() {
        return Hex.encodeHexString(buffer);
    }
}
