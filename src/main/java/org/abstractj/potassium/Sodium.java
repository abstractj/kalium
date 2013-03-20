package org.abstractj.potassium;

import org.abstractj.potassium.util.Loader;

public class Sodium {

    public interface CSodium {
        public int randombytes_random();
    }

    public static void main(String argv[]) {
        CSodium ctest = Loader.lib("/Users/abstractj/hd2/opensource/security/sodium/libsodium-0.3/binaries/lib/libsodium.dylib", CSodium.class);
        System.out.println(ctest.randombytes_random());
    }

}
