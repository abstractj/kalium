package org.abstractj.kalium;

import jnr.ffi.provider.FFIProvider;

public interface NaCl {

    String LIBRARY_NAME = "sodium";

    public static final Sodium SODIUM_INSTANCE = FFIProvider.getSystemProvider()
            .createLibraryLoader(Sodium.class)
            .library(LIBRARY_NAME)
            .load();

    public interface Sodium {

        public String sodium_version_string();

        public int crypto_hash_sha256_ref(byte[] buffer, String message, long sizeof);

        public int crypto_hash_sha512_ref(byte[] buffer, String message, long sizeof);
    }
}