package org.abstractj.halite;

import jnr.ffi.Library;

public class HelloWorld {

    public interface CTest {
        public void helloFromC();
    }

    static public void main(String argv[]) {
        CTest ctest = Library.loadLibrary("/Users/abstractj/hd2/opensource/security/halite/ext/libctest.so", CTest.class);
        ctest.helloFromC();
    }
}
