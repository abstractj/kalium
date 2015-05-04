package org.abstractj.kalium.crypto;

import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.AES128_KEY;
import static org.abstractj.kalium.fixture.TestVectors.AES128_MESSAGE;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_STREAM_AES_128_CTR_NONCEBYTES;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class StreamTest {
	private static Stream stream;
	private static byte[] nonce;

	private static byte[] message = AES128_MESSAGE.getBytes();

	@BeforeClass
	public static void init() {
		Random random = new Random();
		stream = new Stream(HEX.decode(AES128_KEY));

		nonce = random
				.randomBytes(CRYPTO_STREAM_AES_128_CTR_NONCEBYTES);
	}

	@Test
	public void testEncryption() {
		byte[] encryptedMessage = stream.encrypt(nonce, message);
		byte[] decryptedMessage = stream.decrypt(nonce, encryptedMessage);
		
		Assert.assertEquals(AES128_MESSAGE, new String(decryptedMessage));
	}
}
