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

package org.abstractj.kalium.keys;

import org.abstractj.kalium.crypto.Random;
import org.abstractj.kalium.encoders.Encoder;

import static org.abstractj.kalium.NaCl.Sodium.SIGNATURE_PUBLICKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SIGNATURE_SECRETKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SIGNATURE_SEED_BYTES;
import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.crypto.Util.isValid;
import static org.abstractj.kalium.crypto.Util.zeros;

public class SigningKeyPair {
    private final byte[] signingKey;
    private final byte[] verifyKey;

    public SigningKeyPair(byte[] seed) {
        checkLength(seed, SIGNATURE_SEED_BYTES);
        this.signingKey = zeros(SIGNATURE_SECRETKEY_BYTES);
        this.verifyKey = zeros(SIGNATURE_PUBLICKEY_BYTES);
        isValid(sodium().crypto_sign_ed25519_ref_seed_keypair(verifyKey, signingKey, seed),
                "Failed to generate a key pair");
    }

    public SigningKeyPair() {
        this(new Random().randomBytes(SIGNATURE_SEED_BYTES));
    }

    public SigningKeyPair(String seed, Encoder encoder) {
        this(encoder.decode(seed));
    }

    public SigningKey getSigningKey() {
        return new SigningKey(this.signingKey);
    }

    public VerifyKey getVerifyKey() {
        return new VerifyKey(this.verifyKey);
    }
}
