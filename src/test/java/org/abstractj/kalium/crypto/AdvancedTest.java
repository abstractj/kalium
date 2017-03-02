package org.abstractj.kalium.crypto;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 * Created by yi on 02/03/2017.
 */
public class AdvancedTest {

    @Test
    public void testXsalsa20HappyFlow() {
        Random random = new Random();
        Advanced advanced = new Advanced();
        byte[] nonce = random.randomBytes(24);
        byte[] key = random.randomBytes(32);
        String pwd = "This is a test message :-)...";
        byte[] plaintext = pwd.getBytes();
        byte[] ciphertext = advanced.crypto_stream_xsalsa20_xor(plaintext, nonce, key); // encrypt
        plaintext = advanced.crypto_stream_xsalsa20_xor(ciphertext, nonce, key); // decrypt
        assertEquals(pwd, new String(plaintext));
    }

    @Test
    public void testXsalsa20IncorrectNonce() {
        Random random = new Random();
        Advanced advanced = new Advanced();
        byte[] nonce = random.randomBytes(24);
        byte[] incorrectNonce = random.randomBytes(24);
        byte[] key = random.randomBytes(32);
        String pwd = "This is a test message :-)...";
        byte[] plaintext = pwd.getBytes();
        byte[] ciphertext = advanced.crypto_stream_xsalsa20_xor(plaintext, nonce, key); // encrypt
        plaintext = advanced.crypto_stream_xsalsa20_xor(ciphertext, incorrectNonce, key); // decrypt
        assertNotEquals(pwd, new String(plaintext));
    }

    @Test
    public void testXsalsa20IncorrectKey() {
        Random random = new Random();
        Advanced advanced = new Advanced();
        byte[] nonce = random.randomBytes(24);
        byte[] key = random.randomBytes(32);
        byte[] incorrectKey = random.randomBytes(32);
        String pwd = "This is a test message :-)...";
        byte[] plaintext = pwd.getBytes();
        byte[] ciphertext = advanced.crypto_stream_xsalsa20_xor(plaintext, nonce, key); // encrypt
        plaintext = advanced.crypto_stream_xsalsa20_xor(ciphertext, nonce, incorrectKey); // decrypt
        assertNotEquals(pwd, new String(plaintext));
    }

    @Test
    public void testXsalsa20IncorrectKeyAndIncorrectNonce() {
        Random random = new Random();
        Advanced advanced = new Advanced();
        byte[] nonce = random.randomBytes(24);
        byte[] incorrectNonce = random.randomBytes(24);
        byte[] key = random.randomBytes(32);
        byte[] incorrectKey = random.randomBytes(32);
        String pwd = "This is a test message :-)...";
        byte[] plaintext = pwd.getBytes();
        byte[] ciphertext = advanced.crypto_stream_xsalsa20_xor(plaintext, nonce, key); // encrypt
        plaintext = advanced.crypto_stream_xsalsa20_xor(ciphertext, incorrectNonce, incorrectKey); // decrypt
        assertNotEquals(pwd, new String(plaintext));
    }

}
