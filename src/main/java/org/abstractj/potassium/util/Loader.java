package org.abstractj.potassium.util;

import jnr.ffi.LibraryLoader;
import jnr.ffi.provider.FFIProvider;

public class Loader {

    public static final String PATH = "src/main/ext/bin/";

    public static <T> T lib(String libname, Class<T> interfaceClass) {
        LibraryLoader<T> loader = FFIProvider.getSystemProvider().createLibraryLoader(interfaceClass);
//        loader.search(PATH);
        loader.library(libname);
        return loader.load();
    }
}
