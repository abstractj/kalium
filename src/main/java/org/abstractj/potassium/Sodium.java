package org.abstractj.potassium;

import org.abstractj.potassium.util.Loader;

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
