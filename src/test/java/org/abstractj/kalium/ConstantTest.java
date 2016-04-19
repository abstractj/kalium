package org.abstractj.kalium;

import jnr.ffi.LibraryLoader;
import jnr.ffi.types.size_t;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ConstantTest {

    private SodiumConstants lib =
            LibraryLoader.create(SodiumConstants.class)
                    .search("/usr/local/lib")
                    .search("/opt/local/lib")
                    .search("lib")
                    .load("sodium");

    @Test
    public void testSecretBoxConstants() throws Exception {
        assertEquals("CRYPTO_SECRETBOX_KEYBYTES",
                lib.crypto_secretbox_keybytes(),
                NaCl.Sodium.CRYPTO_SECRETBOX_KEYBYTES);

        assertEquals("CRYPTO_SECRETBOX_NONCEBYTES",
                lib.crypto_secretbox_noncebytes(),
                NaCl.Sodium.CRYPTO_SECRETBOX_NONCEBYTES);

        assertEquals("CRYPTO_SECRETBOX_ZEROBYTES",
                lib.crypto_secretbox_zerobytes(),
                NaCl.Sodium.CRYPTO_SECRETBOX_ZEROBYTES);

        assertEquals("CRYPTO_SECRETBOX_BOXZEROBYTES",
                lib.crypto_secretbox_boxzerobytes(),
                NaCl.Sodium.CRYPTO_SECRETBOX_BOXZEROBYTES);

        assertEquals("CRYPTO_SECRETBOX_MACBYTES",
                lib.crypto_secretbox_macbytes(),
                NaCl.Sodium.CRYPTO_SECRETBOX_MACBYTES);
    }

    @Test
    public void testSecretAuthConstants() throws Exception {
        assertEquals("CRYPTO_AUTH_BYTES",
                lib.crypto_auth_bytes(),
                NaCl.Sodium.CRYPTO_AUTH_BYTES);

        assertEquals("CRYPTO_AUTH_KEYBYTES",
                lib.crypto_auth_keybytes(),
                NaCl.Sodium.CRYPTO_AUTH_KEYBYTES);
    }

    @Test
    public void testSecretAEADConstants() throws Exception {
        assertEquals("CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES",
                lib.crypto_aead_chacha20poly1305_keybytes(),
                NaCl.Sodium.CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES);

        assertEquals("CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES",
                lib.crypto_aead_chacha20poly1305_npubbytes(),
                NaCl.Sodium.CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);

        assertEquals("CRYPTO_AEAD_CHACHA20POLY1305_ABYTES",
                lib.crypto_aead_chacha20poly1305_abytes(),
                NaCl.Sodium.CRYPTO_AEAD_CHACHA20POLY1305_ABYTES);
    }

    public interface SodiumConstants {
        @size_t
        int crypto_secretbox_keybytes();

        @size_t
        int crypto_secretbox_noncebytes();

        @size_t
        int crypto_secretbox_zerobytes();

        @size_t
        int crypto_secretbox_boxzerobytes();

        @size_t
        int crypto_secretbox_macbytes();

        @size_t
        int crypto_auth_bytes();

        @size_t
        int crypto_auth_keybytes();

        @size_t
        int crypto_aead_chacha20poly1305_keybytes();

        @size_t
        int crypto_aead_chacha20poly1305_npubbytes();

        @size_t
        int crypto_aead_chacha20poly1305_abytes();
    }
}
