package org.abstractj.kalium.crypto;

import org.junit.Test;

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

}
