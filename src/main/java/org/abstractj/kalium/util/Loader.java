package org.abstractj.kalium.util;

import jnr.ffi.LibraryLoader;
import jnr.ffi.provider.FFIProvider;

public class Loader {

    public static <T> T lib(String libname, Class<T> interfaceClass) {
        LibraryLoader<T> loader = FFIProvider.getSystemProvider().createLibraryLoader(interfaceClass);
        loader.library(libname);
        return loader.load();
    }
}
