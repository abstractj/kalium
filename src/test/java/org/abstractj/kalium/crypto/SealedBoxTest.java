package org.abstractj.kalium.crypto;

import org.junit.Test;

import java.security.SecureRandom;

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_BOX_PUBLICKEYBYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_BOX_SECRETKEYBYTES;
import static org.abstractj.kalium.NaCl.sodium;
import static org.junit.Assert.assertArrayEquals;

public class SealedBoxTest {

    @Test
    public void testEncryptDecrypt() throws Exception {
        SecureRandom r = new SecureRandom();
        byte[] pk = new byte[CRYPTO_BOX_PUBLICKEYBYTES];
        byte[] sk = new byte[CRYPTO_BOX_SECRETKEYBYTES];
        byte[] m = new byte[r.nextInt(1000)];

        sodium().crypto_box_keypair(pk, sk);
        r.nextBytes(m);

        SealedBox sb = new SealedBox(pk);
        byte[] c = sb.encrypt(m);

        SealedBox sb2 = new SealedBox(pk, sk);
        byte[] m2 = sb2.decrypt(c);
        assertArrayEquals(m, m2);
    }

    @Test(expected = RuntimeException.class)
    public void testDecryptFailsFlippedKeys() throws Exception {
        SecureRandom r = new SecureRandom();
        byte[] pk = new byte[CRYPTO_BOX_PUBLICKEYBYTES];
        byte[] sk = new byte[CRYPTO_BOX_SECRETKEYBYTES];
        byte[] m = new byte[r.nextInt(1000)];

        sodium().crypto_box_keypair(pk, sk);
        r.nextBytes(m);

        SealedBox sb = new SealedBox(pk);
        byte[] c = sb.encrypt(m);
        SealedBox sb2 = new SealedBox(sk, pk);
        sb2.decrypt(c);
    }
}
