package org.abstractj.kalium.crypto;

import org.abstractj.kalium.NaCl;
import org.openjdk.jmh.Main;
import org.openjdk.jmh.annotations.GenerateMicroBenchmark;
import org.openjdk.jmh.annotations.State;

@State
public class UtilConstantTimeBench {

    byte[] a = new byte[32];
    byte[] z = new byte[32];

    public UtilConstantTimeBench() {
        NaCl.sodium().randombytes(a, 32);
    }

    @GenerateMicroBenchmark
    public void testNativeNotZero() throws Exception {
        Util.constantTimeIsZero(a);
    }

    @GenerateMicroBenchmark
    public void testNativeZero() throws Exception {
        Util.constantTimeIsZero(z);
    }

    @GenerateMicroBenchmark
    public void testFfiNotZero() throws Exception {
        NaCl.sodium().sodium_is_zero(a, 32);
    }

    @GenerateMicroBenchmark
    public void testFfiZero() throws Exception {
        NaCl.sodium().sodium_is_zero(z, 32);
    }

    public static void main(String[] args) {
        Main.main(args);
    }
}
