package org.abstractj.kalium.crypto;

import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.NaCl.Sodium.AES_128_CTR_KEYBYTES;
import static org.abstractj.kalium.NaCl.Sodium.BOXZERO_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_STREAM_AES_128_CTR_NONCEBYTES;
import static org.abstractj.kalium.NaCl.Sodium.ZERO_BYTES;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.crypto.Util.isValid;
import static org.abstractj.kalium.crypto.Util.prependZeros;
import static org.abstractj.kalium.crypto.Util.removeZeros;

public class Stream {

	private byte[] key;

	public Stream(byte[] key) {
		this.key = key;
		checkLength(key, AES_128_CTR_KEYBYTES);
	}

	public byte[] encrypt(byte[] nonce, byte[] message) {
		checkLength(nonce, CRYPTO_STREAM_AES_128_CTR_NONCEBYTES);
		byte[] msg = prependZeros(ZERO_BYTES, message);
		byte[] ct = new byte[msg.length];

		isValid(sodium().crypto_stream_aes128ctr_xor(ct, msg, msg.length,
				nonce, key), "Encryption failed");

		return removeZeros(BOXZERO_BYTES, ct);
	}

	public byte[] decrypt(byte[] nonce, byte[] ciphertext) {
		checkLength(nonce, CRYPTO_STREAM_AES_128_CTR_NONCEBYTES);
		byte[] ct = prependZeros(BOXZERO_BYTES, ciphertext);
		byte[] message = new byte[ct.length];

		isValid(sodium().crypto_stream_aes128ctr_xor(message, ct,
				message.length, nonce, key), "Decryption failed");

		return removeZeros(ZERO_BYTES, message);
	}

}
