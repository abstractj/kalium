package org.abstractj.kalium;

import jnr.ffi.annotations.In;
import jnr.ffi.annotations.LongLong;
import jnr.ffi.annotations.Out;
import org.abstractj.kalium.util.Loader;

import java.nio.ByteBuffer;

public class Sodium {

    public static final String LIBNAME = "sodium";

    public interface CSodium {
        public int randombytes_random();
        public String sodium_version_string();
        public int crypto_hash_sha256(@Out ByteBuffer p1, @In ByteBuffer p2, @LongLong long l);
        public int crypto_hash_sha512(@Out ByteBuffer p1, @In ByteBuffer p2, @LongLong long l);
    }

    public static void main(String argv[]) {
        CSodium sodium = Loader.lib(LIBNAME, CSodium.class);
        ByteBuffer foo = ByteBuffer.allocateDirect(1000000);
        ByteBuffer bar = ByteBuffer.allocateDirect(1000000);

        try {
            System.out.println("Sodium release: " + sodium.sodium_version_string());
            System.out.println(sodium.crypto_hash_sha512(foo, bar, 1000000L));
        } catch (Exception e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }

    }

}
