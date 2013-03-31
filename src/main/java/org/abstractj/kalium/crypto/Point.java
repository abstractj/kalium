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
import static org.abstractj.kalium.NaCl.Sodium.SCALAR_BYTES;

public class Point {

    private static final Sodium sodium = SODIUM_INSTANCE;
    private static final String STANDARD_GROUP_ELEMENT = "0900000000000000000000000000000000000000000000000000000000000000";

    private byte[] point;
    private byte[] result;

    public Point() {
        this.point = Hex.decodeHexString(STANDARD_GROUP_ELEMENT);
    }

    public Point(String point) {
        this.point = Hex.decodeHexString(point);
    }

    public Point mult(String n) {
        byte[] intValue = Hex.decodeHexString(n);
        result = Util.zeros(SCALAR_BYTES);
        sodium.crypto_scalarmult_curve25519_ref(result, intValue, point);
        return this;
    }

    public String value() {
        return Hex.encodeHexString(result);
    }

    public String toHex() {
        return Hex.encodeHexString(point);
    }

    public byte[] toBytes() {
        return point;
    }
}
