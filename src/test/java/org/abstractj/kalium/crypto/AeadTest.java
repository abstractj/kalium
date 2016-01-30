package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl;
import org.junit.Test;

import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.*;
import static org.junit.Assert.assertArrayEquals;

public class AeadTest {
    @Test
    public void testEncrypt() throws Exception {
        byte[] key = HEX.decode(AEAD_KEY);
        byte[] publicNonce = HEX.decode(AEAD_NONCE);
        byte[] message = HEX.decode(AEAD_MESSAGE);
        byte[] ad = HEX.decode(AEAD_AD);

        Aead aead = new Aead(key);
        byte[] ct = aead.encrypt(publicNonce, message, ad);
        assertArrayEquals(HEX.decode(AEAD_CT), ct);
    }

    @Test
    public void testDecrypt() throws Exception {
        byte[] key = HEX.decode(AEAD_KEY);
        byte[] publicNonce = HEX.decode(AEAD_NONCE);
        byte[] ct = HEX.decode(AEAD_CT);
        byte[] ad = HEX.decode(AEAD_AD);

        Aead aead = new Aead(key);
        byte[] message = aead.decrypt(publicNonce, ct, ad);
        assertArrayEquals(HEX.decode(AEAD_MESSAGE), message);
    }

    @Test
    public void testAES256GCM() throws Exception {
        sodium().sodium_init();
        if (sodium().crypto_aead_aes256gcm_is_available() != 1) {
            System.out.println("AES256-GCM is not supported");
            return;
        }

        byte[] key = HEX.decode(AEAD_KEY);
        byte[] publicNonce = new Random().randomBytes(NaCl.Sodium.CRYPTO_AEAD_AES256GCM_NPUBBYTES);
        byte[] message = HEX.decode(AEAD_MESSAGE);
        byte[] ad = HEX.decode(AEAD_AD);

        Aead aead = new Aead(key).useAesGcm();
        byte[] ct = aead.encrypt(publicNonce, message, ad);
        byte[] msg2 = aead.decrypt(publicNonce, ct, ad);
        assertArrayEquals(message, msg2);
    }
}
