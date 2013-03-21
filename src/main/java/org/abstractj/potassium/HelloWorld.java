package org.abstractj.potassium;

import org.abstractj.potassium.util.Loader;

public class HelloWorld {

    public interface CTest {
        public void helloFromC();
    }

    public static void main(String argv[]) {
        CTest ctest = Loader.lib("ctest", CTest.class);
        ctest.helloFromC();
    }
}
