package org.abstractj.potassium;

import jnr.ffi.LibraryLoader;
import jnr.ffi.provider.FFIProvider;

public class HelloWorld {

    public interface CTest {
        public void helloFromC();
    }

    public static void main(String argv[]) {
        CTest ctest = loadLib("/Users/abstractj/hd2/opensource/security/potassium/ext/libctest.so", CTest.class);
        ctest.helloFromC();
    }

    public static <T> T loadLib(String libname, Class<T> interfaceClass) {
        LibraryLoader<T> loader = FFIProvider.getSystemProvider().createLibraryLoader(interfaceClass);

        loader.library(libname);

        return loader.load();
    }
}
