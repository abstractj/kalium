package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl;
import org.junit.BeforeClass;
import org.junit.Test;

public class StreamTest {
	private static Stream stream;
	private static byte[] key;
	private static byte[] nonce;

	private static byte[] message = "Hello World!".getBytes();

	@BeforeClass
	public static void init() {
		Random random = new Random();
		key = random.randomBytes(NaCl.Sodium.AES_128_CTR_KEYBYTES);

		stream = new Stream(key);

		nonce = random
				.randomBytes(NaCl.Sodium.CRYPTO_STREAM_AES_128_CTR_NONCEBYTES);
	}

	@Test
	public void testEncryption() {
		byte[] encryptedMessage = stream.encrypt(nonce, message);

		byte[] decryptedMessage = stream.decrypt(nonce, encryptedMessage);

		System.out.println(new String(decryptedMessage));
	}
}
