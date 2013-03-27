package org.abstractj.kalium;

import jnr.ffi.LibraryLoader;
import jnr.ffi.provider.FFIProvider;

public class NaCl {

    public static final Sodium SODIUM_INSTANCE;
    private static final String LIBRARY_NAME = "sodium";

    private NaCl() {
    }

    public interface Sodium {

        public String sodium_version_string();

        public int crypto_hash_sha256_ref(byte[] buffer, String message, long sizeof);

        public int crypto_hash_sha512_ref(byte[] buffer, String message, long sizeof);

        public int crypto_box_curve25519xsalsa20poly1305_ref_keypair(byte[] pk, byte[] sk);

        //TODO
        public int crypto_box_curve25519xsalsa20poly1305_ref_afternm(byte[] ct, byte[] msg, int length, byte[] nonce, byte[] beforenm);
        //TODO
        public int crypto_box_curve25519xsalsa20poly1305_ref_beforenm(byte[] k, byte[] publicKey, byte[] privateKey);

        public void randombytes(byte[] buffer, long size);
    }

    static {
        LibraryLoader<Sodium> libraryLoader = FFIProvider.getSystemProvider()
                .createLibraryLoader(Sodium.class)
                .library(LIBRARY_NAME);
        SODIUM_INSTANCE = libraryLoader.load();
    }
}