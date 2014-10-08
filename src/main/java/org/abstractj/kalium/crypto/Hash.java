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

import java.nio.ByteBuffer;

import static org.abstractj.kalium.NaCl.Sodium.BLAKE2B_OUTBYTES;
import static org.abstractj.kalium.NaCl.Sodium.SHA256BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SHA512BYTES;
import static org.abstractj.kalium.NaCl.sodium;

public class Hash {
    /**
     * Like the regular sha256 with the same signature,
     * except without safety checks.
     *
     * @param message The message for which to compute the checksum.
     * @param out The buffer that will have the checksum. Must be a directly
     *            allocated, and of the appropriate capacity.
     */
    private void sha256Unsafe(ByteBuffer message, ByteBuffer out){
        sodium().crypto_hash_sha256(out, message, message.capacity());
    }

    /**
     * Computes a SHA-256 checksum.
     *
     * @param message The message for which to compute the checksum.
     * @param out The buffer that will have the checksum.
     */
	public void sha256(ByteBuffer message, ByteBuffer out) {
        assert out.isDirect();
        assert out.capacity() == SHA256BYTES;
        sha256Unsafe(message, out);
	}

    /**
     * Computes a SHA-256 checksum.
     *
     * @param message The message for which to compute the checksum.
     * @return A new, directly allocated byte buffer with the checksum.
     */
	public ByteBuffer sha256(ByteBuffer message) {
        ByteBuffer out = ByteBuffer.allocateDirect(SHA256BYTES);
        sha256Unsafe(message, out);
        return out;
	}

    public byte[] sha256(byte[] message) {
        // REVIEW: This is unsafe because of byte[]!
        return copyBufferToArray(sha256(ByteBuffer.wrap(message)));
    }

    /**
     * Like the regular sha512 with the same signature,
     * except without safety checks.
     *
     * @param message The message for which to compute the checksum.
     * @param out The buffer that will have the checksum. Must be a directly
     *            allocated, and of the appropriate capacity.
     */
    private void sha512Unsafe(ByteBuffer message, ByteBuffer out){
        sodium().crypto_hash_sha512(out, message, message.capacity());
    }

    /**
     * Computes a SHA-512 checksum.
     *
     * @param message The message for which to compute the checksum.
     * @param out The buffer that will have the checksum.
     */
    public void sha512(ByteBuffer message, ByteBuffer out) {
        assert out.isDirect();
        assert out.capacity() == SHA512BYTES;
        sha512Unsafe(message, out);
    }

    /**
     * Computes a SHA-512 checksum.
     *
     * @param message The message for which to compute the checksum.
     * @return A new, directly allocated byte buffer with the checksum.
     */
    public ByteBuffer sha512(ByteBuffer message) {
        ByteBuffer out = ByteBuffer.allocateDirect(SHA512BYTES);
        sha512Unsafe(message, out);
        return out;
    }

    public byte[] sha512(byte[] message) {
        // REVIEW: This is unsafe because of byte[]!
        return copyBufferToArray(sha512(ByteBuffer.wrap(message)));
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
    /**
     * Copies a ByteBuffer's contents into an array.
     *
     * Since this makes a copy, this is insecure to use with secret data.
     *
     * @param buffer The buffer to make a copy of.
     * @return An independent byte array with the same contents as the buffer.
     */
    private static byte[] copyBufferToArray(ByteBuffer buffer) {
        byte[] result = new byte[buffer.capacity()];
        buffer.get(result, 0, buffer.capacity());
        return result;
    }
}
