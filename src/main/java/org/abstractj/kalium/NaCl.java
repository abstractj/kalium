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

        public static final int SHA256BYTES = 32;

        public int crypto_hash_sha256_ref(byte[] buffer, String message, long sizeof);

        public static final int SHA512BYTES = 64;

        public int crypto_hash_sha512_ref(byte[] buffer, String message, long sizeof);

        public static final int PUBLICKEY_BYTES = 32;
        public static final int SECRETKEY_BYTES = 32;

        public int crypto_box_curve25519xsalsa20poly1305_ref_keypair(byte[] publicKey, byte[] secretKey);


        public static final int CURVE25519_XSALSA20_POLY1305_BOX_NONCE_BYTES = 24;
        public static final int NONCE_BYTES = 24;
        public static final int ZERO_BYTES = 32;
        public static final int BOXZERO_BYTES = 16;
        public static final int CURVE25519_XSALSA20_POLY1305_BOX_BEFORE_NMBYTES = 32;

        public void randombytes(byte[] buffer, long size);

        public int crypto_box_curve25519xsalsa20poly1305_ref(byte[] ct, byte[] msg, int length, byte[] nonce, byte[] publicKey, byte[] privateKey);

        public int crypto_box_curve25519xsalsa20poly1305_ref_open(byte[] message, byte[] ct, int length, byte[] nonce, byte[] publicKey, byte[] privateKey);

        public static final int SCALAR_BYTES = 32;

        public int crypto_scalarmult_curve25519_ref(byte[] result, byte[] intValue, byte[] point);


    }

    static {
        LibraryLoader<Sodium> libraryLoader = FFIProvider.getSystemProvider()
                .createLibraryLoader(Sodium.class)
                .library(LIBRARY_NAME);
        SODIUM_INSTANCE = libraryLoader.load();
    }
}