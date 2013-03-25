package org.abstractj.kalium;

import org.abstractj.kalium.util.Loader;

public class Sodium {

    public static final String LIBNAME = "sodium";

    public interface CSodium {
        public String sodium_version_string();
        public int crypto_hash_sha256_ref(byte[] buffer, String message, long sizeof);
        public int crypto_hash_sha512_ref(byte[] buffer, String message, long sizeof);
    }

    public static CSodium getInstance() {
        return Loader.lib(LIBNAME, CSodium.class);
    }
}