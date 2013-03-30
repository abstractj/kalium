package org.abstractj.kalium.crypto;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

public class Util {

    public static final int DEFAULT_SIZE = 32;
    public static final String CHARSET_NAME = "US-ASCII";

    public static byte[] prependZeros(int n, String message) {
        byte[] buffer = null;
        try {
            buffer = new byte[n + message.getBytes(CHARSET_NAME).length];
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return buffer;
    }

    public static byte[] prependZeros(int n, byte[] message) {
        byte[] result = new byte[n + message.length];
        Arrays.fill(result, (byte) 0);
        System.arraycopy(message, 0, result, n, message.length);
        return result;
    }

    public static byte[] removeZeros(int n, byte[] message) {
        byte[] buffer = Arrays.copyOfRange(message, n, message.length);
        return buffer;
    }

    public static byte[] prependZeros(String message) {
        return prependZeros(DEFAULT_SIZE, message);
    }

    public static byte[] removeZeros(byte[] message) {
        return removeZeros(DEFAULT_SIZE, message);
    }

    public static void checkLength(byte[] data, int size) {
        if (data == null || data.length != size)
            throw new RuntimeException("Invalid key size");
    }

    public static byte[] zeros(int n) {
        return new byte[n];
    }

    public static void isValid(int status) {
        if (status != 0)
            throw new RuntimeException("Invalid key");
    }

    public static void isValid(int status, String message) {
        if (status != 0)
            throw new RuntimeException(message);
    }

}
