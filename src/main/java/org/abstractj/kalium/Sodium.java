package org.abstractj.kalium;

import org.abstractj.kalium.util.Loader;

public class Sodium {

    public static final String LIBNAME = "sodium";

    public interface CSodium {
        public int randombytes_random();
    }

    public static void main(String argv[]) {
        CSodium ctest = Loader.lib(LIBNAME, CSodium.class);
        System.out.println(ctest.randombytes_random());
    }

}
