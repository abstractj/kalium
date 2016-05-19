package org.abstractj.kalium.crypto;

import org.abstractj.kalium.keys.KeyPair;
import org.junit.Test;

import java.security.SecureRandom;

import static org.abstractj.kalium.NaCl.Sodium.PUBLICKEY_BYTES;
import static org.abstractj.kalium.NaCl.Sodium.SECRETKEY_BYTES;
import static org.abstractj.kalium.NaCl.sodium;
import static org.junit.Assert.assertArrayEquals;

public class SealedBoxTest {

    @Test
    public void testEncryptDecrypt() throws Exception {
        SecureRandom r = new SecureRandom();
        KeyPair keyPair = new KeyPair(new byte[SECRETKEY_BYTES]);
        byte[] sk = keyPair.getPrivateKey().toBytes();
        byte[] pk = keyPair.getPublicKey().toBytes();
        byte[] m = new byte[r.nextInt(1000)];

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
        byte[] pk = new byte[PUBLICKEY_BYTES];
        byte[] sk = new byte[SECRETKEY_BYTES];
        byte[] m = new byte[r.nextInt(1000)];

        sodium().crypto_box_curve25519xsalsa20poly1305_keypair(pk, sk);
        r.nextBytes(m);

        SealedBox sb = new SealedBox(pk);
        byte[] c = sb.encrypt(m);
        SealedBox sb2 = new SealedBox(sk, pk);
        sb2.decrypt(c);
    }

    @Test(expected = RuntimeException.class)
    public void testDecryptFailsWithNull() throws Exception {
        SecureRandom r = new SecureRandom();
        byte[] pk = null;
        byte[] sk = null;
        byte[] m = new byte[r.nextInt(1000)];

        SealedBox sb = new SealedBox(pk);
        byte[] c = sb.encrypt(m);
        SealedBox sb2 = new SealedBox(sk, pk);
        sb2.decrypt(c);
    }
}
