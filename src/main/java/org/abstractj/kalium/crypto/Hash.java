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

import org.abstractj.kalium.encoders.Encoder;

import static org.abstractj.kalium.NaCl.Sodium.BLAKE2B_OUTBYTES;
import static org.abstractj.kalium.NaCl.Sodium.SHA256BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SHA512BYTES;
import static org.abstractj.kalium.NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_OUTBYTES;
import static org.abstractj.kalium.NaCl.Sodium.PWHASH_SCRYPTSALSA208SHA256_STRBYTES;
import static org.abstractj.kalium.NaCl.sodium;

public class Hash {

    public byte[] sha256(byte[] message) {
        byte[] buffer = new byte[SHA256BYTES];
        sodium().crypto_hash_sha256(buffer, message, message.length);
        return buffer;
    }

    public byte[] sha512(byte[] message) {
        byte[] buffer = new byte[SHA512BYTES];
        sodium().crypto_hash_sha512(buffer, message, message.length);
        return buffer;
    }

    public String sha256(String message, Encoder encoder) {
        byte[] hash = sha256(message.getBytes());
        return encoder.encode(hash);
    }

    public String sha512(String message, Encoder encoder) {
        byte[] hash = sha512(message.getBytes());
        return encoder.encode(hash);
    }


    public byte[] blake2(byte[] message) throws UnsupportedOperationException {
        byte[] buffer = new byte[BLAKE2B_OUTBYTES];
        sodium().crypto_generichash_blake2b(buffer, BLAKE2B_OUTBYTES, message, message.length, null, 0);
        return buffer;
    }

    public String blake2(String message, Encoder encoder) throws UnsupportedOperationException {
        byte[] hash = blake2(message.getBytes());
        return encoder.encode(hash);
    }

    public byte[] blake2(byte[] message, byte[] key, byte[] salt, byte[] personal) throws UnsupportedOperationException {
        byte[] buffer = new byte[BLAKE2B_OUTBYTES];
        sodium().crypto_generichash_blake2b_salt_personal(buffer, BLAKE2B_OUTBYTES,
                                                          message, message.length,
                                                          key, key.length,
                                                          salt, personal);
        return buffer;
    }

    public String pwhash(byte[] passwd, Encoder encoder, byte[] salt, int opslimit, long memlimit) {
        byte[] buffer = new byte[PWHASH_SCRYPTSALSA208SHA256_OUTBYTES];
        sodium().crypto_pwhash_scryptsalsa208sha256(buffer, buffer.length, passwd, passwd.length, salt, opslimit, memlimit);
        return encoder.encode(buffer);
    }

    public String pwhash_str(byte[] passwd, Encoder encoder, int opslimit, long memlimit) {
        byte[] buffer = new byte[PWHASH_SCRYPTSALSA208SHA256_STRBYTES];
        sodium().crypto_pwhash_scryptsalsa208sha256_str(buffer, passwd, passwd.length, opslimit, memlimit);
        return encoder.encode(buffer);
    }

    public boolean pwhash_str_verify(byte[] hashed_passwd, byte[] passwd) {
        int result = sodium().crypto_pwhash_scryptsalsa208sha256_str_verify(hashed_passwd, passwd, passwd.length);
        return result == 0;
    }
}
