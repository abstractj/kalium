/**
 * Copyright 2013,2017 Bruno Oliveira, and individual contributors
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

import org.abstractj.kalium.encoders.Encoder;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.crypto.Util.isValid;
import static org.abstractj.kalium.encoders.Encoder.HEX;

public class SharedKey implements Key {

    private final byte[] sharedKey;

    public SharedKey(byte[] sharedKey) {
        checkLength(sharedKey, CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES);
        this.sharedKey = sharedKey;
    }

    public SharedKey(String sharedKey, Encoder encoder) {
        this(encoder.decode(sharedKey));
    }

    public SharedKey(String sharedKey) {
        this(sharedKey, HEX);
    }

    public SharedKey(byte[] publicKey, byte[] privateKey) {
        checkLength(publicKey, CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES);
        checkLength(privateKey, CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES);

        sharedKey = new byte[CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES];
        isValid(sodium().crypto_box_curve25519xsalsa20poly1305_beforenm(
                sharedKey, publicKey, privateKey), "Key agreement failed");
    }

    public SharedKey(PublicKey publicKey, PrivateKey privateKey) {
        this(publicKey.toBytes(), privateKey.toBytes());
    }

    public SharedKey(String publicKey, String privateKey, Encoder encoder) {
        this(encoder.decode(publicKey), encoder.decode(privateKey));
    }

    public SharedKey(String publicKey, String privateKey) {
        this(publicKey, privateKey, HEX);
    }

    @Override
    public byte[] toBytes() {
        return sharedKey;
    }

    @Override
    public String toString() {
        return HEX.encode(sharedKey);
    }
}
