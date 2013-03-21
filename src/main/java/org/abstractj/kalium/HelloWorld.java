package org.abstractj.kalium;

import org.abstractj.kalium.util.Loader;

public class HelloWorld {

    public interface CTest {
        public void helloFromC();
    }

    public static void main(String argv[]) {
        CTest ctest = Loader.lib("ctest", CTest.class);
        ctest.helloFromC();
    }
}
